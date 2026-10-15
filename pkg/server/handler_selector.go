package server

import (
	"html/template"
	"net/http"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// handleLoginSelector is the front door when no provider authenticated a
// request and several are advertised: it lists the advertised providers'
// login entries so the user picks how to sign in. With a single
// advertised provider it forwards straight to that provider's login
// entry — the page only ever renders when there is an actual choice to
// make. Providers left out of authMode don't appear here but remain
// fully functional via their direct login paths.
//
// The page is public and unauthenticated by design (it is just links,
// like /client.js); return_to is restricted to same-origin relative
// paths so the entries can't be abused as open redirects.
func (s *Server) handleLoginSelector(w http.ResponseWriter, r *http.Request) {
	returnTo := protection.SafeReturnTo(r.URL.Query().Get("return_to"))

	entries := make([]selectorEntry, 0, len(s.advertised))
	for _, np := range s.advertised {
		loginURL := np.Provider.LoginURL(returnTo)
		if loginURL == "" {
			continue
		}
		entries = append(entries, selectorEntry{Name: np.Name, URL: loginURL})
	}

	if len(entries) == 0 {
		http.Error(w, "no interactive login available", http.StatusNotFound)
		return
	}
	if len(entries) == 1 {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, entries[0].URL, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := selectorTmpl.Execute(w, selectorData{Entries: entries}); err != nil {
		s.log.WithError(err).Warn("render login selector")
	}
}

type selectorEntry struct {
	Name string
	URL  string
}

type selectorData struct {
	Entries []selectorEntry
}

var selectorTmpl = template.Must(template.New("selector").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>authenticatoor — sign in</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; background: #f5f5f5; margin: 0; padding: 2rem; color: #222; }
.box { max-width: 26rem; margin: 4rem auto; background: #fff; padding: 2rem; border-radius: .5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
h1 { margin: 0 0 .5rem; font-size: 1.25rem; }
p { margin: 0 0 1.25rem; font-size: .875rem; color: #555; }
a.provider { display: block; margin-bottom: .75rem; padding: .625rem 1rem; background: #2563eb; color: #fff; border-radius: .25rem; font-size: 1rem; text-align: center; text-decoration: none; }
a.provider:hover { background: #1d4ed8; }
</style>
</head>
<body>
<div class="box">
<h1>Sign in</h1>
<p>Choose how to authenticate.</p>
{{range .Entries}}<a class="provider" href="{{.URL}}">{{.Name}}</a>
{{end}}</div>
</body>
</html>
`))
