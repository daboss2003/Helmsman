package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/daboss2003/Helmsman/internal/audit"
	"github.com/daboss2003/Helmsman/internal/github"
	"github.com/daboss2003/Helmsman/internal/gitstore"
)

// "Connect with GitHub": a standard OAuth web flow that lets the operator pick a repo
// and have Helmsman install a READ-ONLY deploy key for it — no key pasting. The OAuth
// token is used only to list repos + install the key; fetching uses the repo-scoped
// deploy key over SSH with a pinned known_hosts.
//
// CSRF/cookie note: the callback is a cross-site top-level navigation back from
// github.com, so the SameSite=Strict session cookie is NOT sent on it. The callback is
// therefore authenticated by a single-use, SameSite=Lax OAuth STATE cookie that only
// an authenticated + CSRF-checked connect action could have set — the standard OAuth
// CSRF defense. Everything after the callback redirects same-site, where the session
// cookie applies again.

// githubRepoView is one row in the repo picker.
type githubRepoView struct {
	FullName      string
	Private       bool
	DefaultBranch string
}

func (s *Server) githubEnabled() bool {
	return s.githubClient != nil && s.gitStore != nil && s.cfg.GitHub.Enabled()
}

func (s *Server) ghStateCookieName() string { return s.cfg.Cookie.Prefix + "ghstate" }

// githubRedirectURI is the OAuth callback URL. The operator registers this exact URL
// on their GitHub OAuth App. Behind the managed edge it's https://<admin hostname>;
// over the loopback tunnel it's http://<host> (a secure context for the browser).
func (s *Server) githubRedirectURI(r *http.Request) string {
	host, scheme := r.Host, "http"
	if s.cfg.Admin.Hostname != "" {
		host, scheme = s.cfg.Admin.Hostname, "https"
	} else if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + host + "/github/callback"
}

func (s *Server) setGhState(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.ghStateCookieName(), Value: state, Path: s.cookiePath(),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
}

func (s *Server) clearGhState(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.ghStateCookieName(), Value: "", Path: s.cookiePath(),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// handleGitHubConnect (POST, auth+CSRF) starts the OAuth flow: mint a state, stash it
// in a Lax cookie, and redirect the browser to GitHub.
func (s *Server) handleGitHubConnect(w http.ResponseWriter, r *http.Request) {
	if !s.githubEnabled() {
		notFound(w)
		return
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(b)
	s.setGhState(w, state)
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "github_connect_start", Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, s.githubClient.AuthorizeURL(s.cfg.GitHub.ClientID, s.githubRedirectURI(r), state), http.StatusSeeOther)
}

// handleGitHubCallback (GET, auth-EXEMPT, state-cookie-gated) finishes OAuth: verify
// state, exchange the code, store the (encrypted) token, then bounce to the picker.
func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	if !s.githubEnabled() {
		notFound(w)
		return
	}
	c, cerr := r.Cookie(s.ghStateCookieName())
	s.clearGhState(w) // single-use, regardless of outcome
	qstate := r.URL.Query().Get("state")
	if cerr != nil || c.Value == "" || qstate == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(qstate)) != 1 {
		_ = s.audit.Log(r.Context(), audit.Event{IP: ClientIP(r.Context()).String(), Action: "github_callback", Outcome: audit.Deny, Level: audit.Security, Detail: "bad or missing oauth state"})
		notFound(w)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "github authorization failed", http.StatusBadRequest)
		return
	}
	token, err := s.githubClient.ExchangeCode(r.Context(), s.cfg.GitHub.ClientID, s.cfg.GitHub.ClientSecret, code, s.githubRedirectURI(r))
	if err != nil {
		s.log.Warn("github token exchange failed", "err", err)
		http.Error(w, "github authorization failed", http.StatusBadGateway)
		return
	}
	login, err := s.githubClient.Viewer(r.Context(), token)
	if err != nil {
		http.Error(w, "github authorization failed", http.StatusBadGateway)
		return
	}
	if err := s.gitStore.SaveGitHubConn(r.Context(), login, token); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Action: "github_connected", Outcome: audit.OK, Level: audit.Security, Detail: "as " + login})
	http.Redirect(w, r, "/github/repos", http.StatusSeeOther)
}

// handleGitHubRepos (GET, auth) shows the repo picker.
func (s *Server) handleGitHubRepos(w http.ResponseWriter, r *http.Request) {
	if !s.githubEnabled() {
		notFound(w)
		return
	}
	conn, ok, err := s.gitStore.GitHubConn(r.Context())
	if err != nil || !ok {
		http.Redirect(w, r, "/git/new", http.StatusSeeOther)
		return
	}
	repos, err := s.githubClient.ListRepos(r.Context(), conn.Token)
	if err != nil {
		s.log.Warn("github list repos failed", "err", err)
		http.Error(w, "could not list repositories from github", http.StatusBadGateway)
		return
	}
	out := make([]githubRepoView, 0, len(repos))
	for _, rp := range repos {
		out = append(out, githubRepoView{FullName: rp.FullName, Private: rp.Private, DefaultBranch: rp.DefaultBranch})
	}
	s.render(w, r, "github_repos.html", tmplData{
		Title:       "Connect a repository — Helmsman",
		CSRFToken:   CSRFToken(r.Context()),
		GitHubLogin: conn.Login,
		GitHubRepos: out,
	})
}

// handleGitHubConnectRepo (POST, auth+CSRF) installs a deploy key on the chosen repo
// and saves it as a new app — the one click that replaces all the manual key/URL
// plumbing.
func (s *Server) handleGitHubConnectRepo(w http.ResponseWriter, r *http.Request) {
	if !s.githubEnabled() {
		notFound(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	slug := strings.TrimSpace(r.PostFormValue("slug"))
	fullName := strings.TrimSpace(r.PostFormValue("full_name"))
	branch := strings.TrimSpace(r.PostFormValue("branch"))
	composePath := strings.TrimSpace(r.PostFormValue("compose_path"))
	if composePath == "" {
		composePath = "docker-compose.yml"
	}
	if branch == "" {
		branch = "main"
	}
	owner, name, ok := splitFullName(fullName)
	if !ok || !provisionSlugRe.MatchString(slug) {
		http.Error(w, "invalid repository or app name", http.StatusBadRequest)
		return
	}
	if s.cfg.IsProtectedProject(slug) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	conn, ok, err := s.gitStore.GitHubConn(r.Context())
	if err != nil || !ok {
		http.Redirect(w, r, "/git/new", http.StatusSeeOther)
		return
	}
	// Generate a fresh read-only deploy key and install it on the repo.
	key, err := github.GenerateDeployKey("helmsman:" + slug)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.githubClient.CreateDeployKey(r.Context(), conn.Token, owner, name, "helmsman:"+slug, key.PublicLine); err != nil && err != github.ErrKeyExists {
		s.log.Warn("github create deploy key failed", "err", err)
		http.Error(w, "could not install the deploy key on github", http.StatusBadGateway)
		return
	}
	kh := github.KnownHosts
	in := gitstore.SaveInput{
		Project:     slug,
		RepoURL:     "git@github.com:" + owner + "/" + name + ".git",
		Ref:         "refs/heads/" + branch,
		ComposePath: composePath,
		BuildPolicy: "never",
		NewCred:     &key.PrivatePEM,
		CredKind:    "ssh",
		KnownHosts:  kh,
	}
	if err := s.gitStore.Save(r.Context(), in); err != nil {
		http.Error(w, "repository config rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "github_connect_repo", Target: slug, Outcome: audit.OK, Level: audit.Security, Detail: fullName})
	http.Redirect(w, r, "/apps/"+slug+"/git", http.StatusSeeOther)
}

// handleGitHubDisconnect (POST, auth+CSRF) forgets the OAuth token. Existing per-repo
// deploy keys keep working.
func (s *Server) handleGitHubDisconnect(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		notFound(w)
		return
	}
	if err := s.gitStore.DeleteGitHubConn(r.Context()); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "github_disconnect", Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/git/new", http.StatusSeeOther)
}

// splitFullName splits "owner/name" with light validation (no path traversal, single
// slash). The GitHub API call path-escapes these anyway.
func splitFullName(full string) (owner, name string, ok bool) {
	parts := strings.Split(full, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	if strings.ContainsAny(full, " \t\n\\") || strings.Contains(full, "..") {
		return "", "", false
	}
	return parts[0], parts[1], true
}
