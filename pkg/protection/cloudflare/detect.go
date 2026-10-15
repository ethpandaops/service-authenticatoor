package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AUD tag detection. When verifyJWT is on but no audTag is configured,
// the provider learns its CF Access application's AUD tag by requesting
// its own login path through the public URL: Cloudflare answers an
// unauthenticated request with a redirect to
// https://<team>/cdn-cgi/access/login/<host>?kid=<aud>&meta=<jwt>, where
// the meta token is signed with the team's keys and names the
// application (aud) and the requested hostname. The detected tag only
// gates the provider's own prefix (login entry and token alias) — the
// routes that are publicly reachable while the edge still covers /auth/*.
const (
	// detectRetryInterval paces detection attempts until a tag is found.
	// The edge may start covering the login prefix at any time, without
	// a redeploy, so attempts continue indefinitely.
	detectRetryInterval = time.Minute
	// detectRefreshInterval re-checks a detected tag, picking up a
	// recreated CF Access application.
	detectRefreshInterval = time.Hour
	// detectMinInterval rate-limits on-demand attempts triggered by
	// requests arriving before a tag is known.
	detectMinInterval = 10 * time.Second
	// detectTimeout bounds a single probe request.
	detectTimeout = 10 * time.Second
)

// cfLoginPathPrefix is the path of Cloudflare Access' login redirect.
const cfLoginPathPrefix = "/cdn-cgi/access/login/"

// detecting reports whether the AUD tag is detected rather than
// configured.
func (p *Provider) detecting() bool {
	return p.cfg.VerifyJWT && p.cfg.AudTag == "" && p.cfg.PublicURL != ""
}

// detectedAudTag returns the detected AUD tag, or "" when unknown.
func (p *Provider) detectedAudTag() string {
	if aud := p.detectedAud.Load(); aud != nil {
		return *aud
	}
	return ""
}

// ensureAud returns the detected AUD tag, running an on-demand detection
// attempt when none is known yet. It never waits for an attempt already
// in flight: that attempt's probe may itself be the request being served.
func (p *Provider) ensureAud(ctx context.Context) string {
	if aud := p.detectedAudTag(); aud != "" {
		return aud
	}
	if !p.detectMu.TryLock() {
		return ""
	}
	defer p.detectMu.Unlock()
	if p.cfg.Now().Sub(p.lastDetect) < detectMinInterval {
		return ""
	}
	p.runDetection(ctx)
	return p.detectedAudTag()
}

// runDetection performs one attempt and stores the result. A failed
// attempt keeps a previously detected tag. Callers hold detectMu.
func (p *Provider) runDetection(ctx context.Context) {
	p.lastDetect = p.cfg.Now()
	aud, err := p.detectAud(ctx)
	if err != nil {
		p.log.WithError(err).Debug("cf access aud tag detection failed")
		return
	}
	if prev := p.detectedAudTag(); prev != aud {
		p.log.WithField("aud", aud).WithField("previous", prev).
			Info("cf access aud tag detected; enforced on " + p.cfg.LoginPath)
		p.detectedAud.Store(&aud)
	}
}

// detectLoop runs detection attempts until ctx is cancelled: every
// detectRetryInterval until a tag is known, then every
// detectRefreshInterval.
func (p *Provider) detectLoop(ctx context.Context) {
	defer p.wg.Done()
	for {
		p.detectMu.Lock()
		p.runDetection(ctx)
		p.detectMu.Unlock()

		wait := detectRetryInterval
		if p.detectedAudTag() != "" {
			wait = detectRefreshInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// detectAud requests the login path through the public URL and extracts
// the AUD tag from Cloudflare's login redirect, verifying the meta token
// against the team's keys and its hostname against the public URL.
func (p *Provider) detectAud(ctx context.Context) (string, error) {
	pub, err := url.Parse(p.cfg.PublicURL)
	if err != nil || pub.Hostname() == "" {
		return "", fmt.Errorf("invalid public URL %q", p.cfg.PublicURL)
	}
	probe := strings.TrimRight(p.cfg.PublicURL, "/") + p.cfg.LoginPath

	ctx, cancel := context.WithTimeout(ctx, detectTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
	if err != nil {
		return "", fmt.Errorf("build probe request: %w", err)
	}
	client := *p.cfg.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("probe %s: %w", probe, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("probe %s: status %d, not a Cloudflare Access redirect "+
			"(is the path covered by the CF Access application?)", probe, resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		return "", fmt.Errorf("probe %s: redirect without location: %w", probe, err)
	}
	if !strings.EqualFold(loc.Host, teamHost(p.cfg.TeamDomain)) ||
		!strings.HasPrefix(loc.Path, cfLoginPathPrefix) {
		return "", fmt.Errorf("probe %s: redirect to %s is not the team's Access login",
			probe, loc.Host+loc.Path)
	}

	meta := loc.Query().Get("meta")
	if meta == "" {
		return "", errors.New("access login redirect carries no meta token")
	}
	claims, err := p.meta.VerifyMeta(ctx, meta)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(claims.Hostname, pub.Hostname()) {
		return "", fmt.Errorf("meta token hostname %q does not match public URL host %q",
			claims.Hostname, pub.Hostname())
	}
	return claims.Audience[0], nil
}

// teamHost strips an optional scheme and trailing slash from a team
// domain.
func teamHost(team string) string {
	team = strings.TrimPrefix(team, "https://")
	team = strings.TrimPrefix(team, "http://")
	return strings.TrimSuffix(team, "/")
}
