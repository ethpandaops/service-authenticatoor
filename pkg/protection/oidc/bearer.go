package oidc

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// maxBearerHeader is the longest Authorization header value the bearer
// path looks at. A longer one is refused before anything is parsed.
const maxBearerHeader = 16 << 10

// bearerScheme is the Authorization scheme of the bearer path, with the
// space that separates it from the token.
const bearerScheme = "Bearer "

// BearerConfig lets non-browser clients (a CLI) authenticate with a JWT
// they already hold from the IdP, sent as "Authorization: Bearer <JWT>".
// The identity is derived from the token's claims by the function the
// login callback uses, so it is the one a browser login gives.
type BearerConfig struct {
	// Audiences are the accepted "aud" values (client ids at the IdP):
	// a token must name at least one. Required; never defaulted to the
	// provider's own ClientID.
	Audiences []string
	// IssuerURL is the issuer of the accepted tokens when it is not
	// Config.IssuerURL (an IdP with one issuer per client). Its
	// discovery document is then fetched separately at Start (a
	// failure fails Start) and its JWKS loaded separately (a failure
	// does not; see newIDTokenVerifier).
	IssuerURL string
}

// startBearer prepares the verifier of the bearer path. It reuses the
// provider's JWKS when the tokens come from the same issuer and runs a
// second discovery otherwise. It warns when the provider's own client
// id is an accepted audience of its own issuer.
func (p *Provider) startBearer(ctx context.Context) error {
	cfg := p.cfg.Bearer
	if cfg == nil {
		return nil
	}
	if len(cfg.Audiences) == 0 {
		return errors.New("oidc: Bearer.Audiences is required")
	}

	verifier := &idTokenVerifier{
		kf: p.verifier.kf, issuer: p.disco.Issuer, audiences: cfg.Audiences, now: p.cfg.Now,
	}
	if cfg.IssuerURL != "" && strings.TrimRight(cfg.IssuerURL, "/") != strings.TrimRight(p.cfg.IssuerURL, "/") {
		disco, err := fetchDiscovery(ctx, p.httpClient, cfg.IssuerURL)
		if err != nil {
			return err
		}
		if verifier, err = newIDTokenVerifier(ctx, disco.JWKSURI, disco.Issuer, cfg.Audiences, p.cfg.Now); err != nil {
			return err
		}
	}
	p.bearer = verifier

	if verifier.issuer == p.disco.Issuer && slices.Contains(cfg.Audiences, p.cfg.ClientID) {
		p.log.WithField("clientID", p.cfg.ClientID).
			Warn("oidc bearer audiences include this provider's own clientId: the id_tokens the IdP issues " +
				"in the browser login of that client are then accepted as bearer credentials too, so " +
				"whoever obtains one — anything the browser flow hands it to — can fetch tokens as its " +
				"user until it expires. List a dedicated client instead")
	}

	p.log.WithFields(logrus.Fields{
		"issuer":    verifier.issuer,
		"audiences": cfg.Audiences,
		"loginPath": p.cfg.LoginPath,
	}).Info("oidc bearer tokens are accepted: a token of this issuer for one of these audiences " +
		"authenticates its user without a browser login")
	return nil
}

// AmbientEnabled reports whether bearer tokens are configured. Only
// then does the server mount the token alias (/<name>/token).
func (p *Provider) AmbientEnabled() bool { return p.cfg.Bearer != nil }

// bearerToken returns the value of the request's Authorization header
// after the Bearer scheme. presented is false when the request has no
// such header (none at all, or one of another scheme).
func bearerToken(r *http.Request) (token string, presented bool) {
	header := r.Header.Get("Authorization")
	if len(header) < len(bearerScheme) || !strings.EqualFold(header[:len(bearerScheme)], bearerScheme) {
		return "", false
	}
	return strings.TrimSpace(header[len(bearerScheme):]), true
}

// bearerChallenge is the unauthenticated outcome of the bearer path:
// 401 with a Bearer challenge, never a redirect.
func bearerChallenge(challenge string) protection.Outcome {
	header := make(http.Header, 1)
	header.Set("WWW-Authenticate", challenge)
	return protection.Outcome{Status: http.StatusUnauthorized, Challenge: header}
}

// AuthenticateAmbient authenticates a request from the JWT in its
// Authorization: Bearer header and nothing else — no session cookie is
// read or set, and the outcome never redirects. The server mounts the
// token alias (/<name>/token) on top of it; that alias is the only
// place a bearer token is accepted (Authenticate, which serves /auth/*,
// does not read the header).
//
// A header longer than maxBearerHeader is refused before its token is
// looked at.
//
// The token must be signed by the bearer issuer (RS256), name that
// issuer and one of the configured audiences, be unexpired and carry a
// subject; there is no nonce to check. The identity then comes from
// identify, as for a browser login. Teams and grant members are
// evaluated for this request and stored nowhere, so the bounds of a
// session cookie do not apply to them.
func (p *Provider) AuthenticateAmbient(_ context.Context, r *http.Request) (protection.Outcome, error) {
	if p.bearer == nil {
		return protection.Outcome{Status: http.StatusUnauthorized}, nil
	}
	token, presented := bearerToken(r)
	if !presented {
		return bearerChallenge("Bearer"), nil
	}
	fail := func(reason error) (protection.Outcome, error) {
		// Debug: anyone can send a bad token, as often as they like.
		// The access log has the request and its 401.
		p.log.WithError(reason).Debug("oidc bearer authentication failed")
		return bearerChallenge(`Bearer error="invalid_token"`), nil
	}
	if len(r.Header.Get("Authorization")) > maxBearerHeader {
		return fail(errors.New("authorization header too large"))
	}
	claims, err := p.bearer.parse(token)
	if err != nil {
		return fail(err)
	}

	id, refusal := p.identify(claims, token, true)
	if refusal != "" {
		// Authenticated, but not let in: identify logged why (at debug
		// level, as everything it says on this path).
		return protection.Outcome{Status: http.StatusForbidden}, nil
	}
	identity := &protection.Identity{
		Subject:        id.subject,
		Email:          id.email,
		SubjectIsEmail: id.email != "",
		Teams:          p.teams.ForRequest(id.attrs),
		Matches:        p.members.ForRequest(id.attrs),
	}
	p.log.WithFields(logrus.Fields{
		"sub":   identity.Subject,
		"teams": identity.Teams,
	}).Info("oidc bearer authentication succeeded")
	return protection.Outcome{Identity: identity}, nil
}
