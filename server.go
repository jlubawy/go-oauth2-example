// +build ignore

package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/sessions"
	"github.com/jlubawy/go-oauth2-example/config"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

const (
	SessionName = "session"
)

var UserDatabase = map[string]string{
	"admin": "password",
}

var oauthConfig = &oauth2.Config{
	ClientID:     config.ClientID,
	ClientSecret: config.ClientSecret,
	Scopes:       []string{"SCOPE1", "SCOPE2"},
	Endpoint: oauth2.Endpoint{
		AuthURL:  "http://localhost:8080/resource/oauth2/authorize",
		TokenURL: "http://localhost:8080/resource/oauth2/token",
	},
}

var cookieStoreSecret = []byte("something-very-secret")

var store = sessions.NewCookieStore(cookieStoreSecret)

func init() {
	gob.Register(&oauth2.Token{})
}

func main() {
	// Authorization server handlers
	http.Handle("/resource/logout", handle(ResourceLogoutHandler))
	http.Handle("/resource/oauth2/authorize", handle(ResourceOAuthAuthorizeHandler))
	http.Handle("/resource/oauth2/authorize/approve", handle(ResourceOAuthAuthorizeApproveHandler))
	http.Handle("/resource/oauth2/token", handle(OAuthTokenHandler))

	// Resource server handlers
	http.Handle("/resource/secret", handle(ResouceSecretHandler))

	// Client server handlers
	http.Handle("/", handle(ClientIndexHandler))
	http.Handle("/client/callback", handle(ClientCallbackHandler))
	http.Handle("/client/logout", handle(ClientLogoutHandler))
	http.Handle("/client/secret", handle(ClientSecretHandler))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

type handle func(w http.ResponseWriter, req *http.Request) error

func (h handle) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Handler panic: %v", r)
		}
	}()
	if err := h(w, req); err != nil {
		log.Printf("Handler error: %v", err)

		if httpErr, ok := err.(Error); ok {
			http.Error(w, httpErr.Message, httpErr.Code)
		}
	}
}

type Error struct {
	Code    int
	Message string
}

func (e Error) Error() string {
	if e.Message == "" {
		e.Message = http.StatusText(e.Code)
	}
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

var (
	ErrClientIDOrSecret          = Error{http.StatusBadRequest, "invalid client ID or secret"}
	ErrInvalidAuthCode           = Error{http.StatusBadRequest, "invalid authorization code"}
	ErrInvalidOAuthResponseType  = Error{http.StatusBadRequest, "invalid OAuth response type"}
	ErrInvalidRedirectURI        = Error{http.StatusBadRequest, "redirect URI is invalid"}
	ErrInvalidUsernameOrPassword = Error{http.StatusBadRequest, "invalid username or password"}
	ErrPasswordEmpty             = Error{http.StatusBadRequest, "password cannot be empty"}
	ErrUsernameEmpty             = Error{http.StatusBadRequest, "username cannot be empty"}
)

func ResourceLogoutHandler(w http.ResponseWriter, req *http.Request) error {
	session, _ := store.Get(req, SessionName)
	session.Values["username"] = nil
	session.Save(req, w)

	if redirectURI := req.FormValue("redirect_uri"); redirectURI != "" {
		http.Redirect(w, req, redirectURI, http.StatusFound)
		return nil
	}

	return nil
}

func ResourceOAuthAuthorizeHandler(w http.ResponseWriter, req *http.Request) error {
	switch req.FormValue("response_type") {
	case "code":
		var (
			username string
			password string
		)

		session, _ := store.Get(req, SessionName)

		switch req.Method {
		case http.MethodGet:
			if redirectURI := req.FormValue("redirect_uri"); redirectURI != "" {
				session.Values["redirect_uri"] = redirectURI
				session.Save(req, w)
			}

			var data = struct {
				Username    interface{}
				RedirectURI string
			}{
				Username:    session.Values["username"],
				RedirectURI: req.RequestURI,
			}

			return oauthAuthorizeTempl.Execute(w, &data)

		case http.MethodPost:
			username = req.FormValue("username")
			password = req.FormValue("password")

			if username == "" {
				return ErrUsernameEmpty
			}
			if password == "" {
				return ErrPasswordEmpty
			}

			checkPassword, ok := UserDatabase[username]
			if !ok {
				return ErrInvalidUsernameOrPassword
			}

			if checkPassword == password {
				// Authenticated, store username so we are authenticated next time
				session.Values["username"] = username
				session.Save(req, w)

				return OAuthCodeRedirect(session, w, req)
			}

			return ErrInvalidUsernameOrPassword

		default:
			http.Error(w, fmt.Sprintf("method %s is not allowed", req.Method), http.StatusMethodNotAllowed)
		}

		return nil

	default:
		return ErrInvalidOAuthResponseType
	}
}

var oauthAuthorizeTempl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html>
  <head>
    <title>OAuth2 Authorization</title>

    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
  </head>
  <body class="container-fluid">
    <div class="row">
      <div class="col-xs-4 col-xs-offset-4">
{{with .Username}}
        Approve access for: {{.}}
        <form method="POST" action="/resource/oauth2/authorize/approve">
          <button type="submit" class="btn btn-default">Approve</button>
        </form>
        <form method="GET" action="/resource/logout">
          <input type="hidden" name="redirect_uri" value="{{$.RedirectURI}}" />
          <button type="submit" class="btn btn-default">Logout</button>
        </form>
{{else}}
        <form method="POST">
          <div class="form-group">
            <label for="inputUsername">Username</label>
            <input type="text" class="form-control" id="inputUsername" name="username" placeholder="Username" value="admin" />
          </div>
          <div class="form-group">
            <label for="inputPassword">Password</label>
            <input type="password" class="form-control" id="inputPassword" name="password" placeholder="Password" value="password" />
          </div>
          <button type="submit" class="btn btn-default">Submit</button>
        </form>
{{end}}
      </div>
    </div>
  </body>
</html>
`))

func ResourceOAuthAuthorizeApproveHandler(w http.ResponseWriter, req *http.Request) error {
	session, _ := store.Get(req, SessionName)
	if session.Values["username"] != nil {
		return OAuthCodeRedirect(session, w, req)
	}
	return nil
}

func OAuthCodeRedirect(session *sessions.Session, w http.ResponseWriter, req *http.Request) error {
	v, ok := session.Values["redirect_uri"]
	if !ok {
		return ErrInvalidRedirectURI
	}

	redirectURI, ok := v.(string)
	if !ok {
		return ErrInvalidRedirectURI
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return err
	}

	values := redirectURL.Query()
	values.Set("code", config.AuthorizeCode)
	redirectURL.RawQuery = values.Encode()
	http.Redirect(w, req, redirectURL.String(), http.StatusFound)
	return nil
}

var (
	ErrUnauthorized = Error{Code: http.StatusUnauthorized}
)

func ResouceSecretHandler(w http.ResponseWriter, req *http.Request) error {
	tokens, ok := req.Header["Authorization"]
	if ok && len(tokens) > 0 {
		accessToken := strings.TrimPrefix(tokens[0], "Bearer ")

		if accessToken == config.AccessToken {
			fmt.Fprintln(w, "secret")
			return nil
		}
	}

	return ErrUnauthorized
}

func OAuthTokenHandler(w http.ResponseWriter, req *http.Request) error {
	code := req.FormValue("code")

	clientID, clientSecret, ok := req.BasicAuth()
	if !ok {
		return ErrClientIDOrSecret
	}
	if clientID != config.ClientID || clientSecret != config.ClientSecret {
		return ErrClientIDOrSecret
	}

	if code != config.AuthorizeCode {
		return ErrInvalidAuthCode
	}

	tok := oauth2.Token{
		AccessToken: config.AccessToken,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(&tok)
}

var (
	ErrEmptyAuthCode      = Error{http.StatusBadRequest, "authorization code cannot be empty"}
	ErrInvalidResourceURI = Error{http.StatusBadRequest, "resource URI is invalid"}
)

func ClientIndexHandler(w http.ResponseWriter, req *http.Request) error {
	return clientIndexTempl.Execute(w, nil)
}

var clientIndexTempl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html>
  <head>
    <title>Client Home</title>

    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
  </head>
  <body class="container-fluid">
    <div class="row">
      <div class="col-xs-4 col-xs-offset-4">
        <p>Access the <a href="/client/secret">secret</a>.</p>
      </div>
    </div>
  </body>
</html>
`))

func ClientCallbackHandler(w http.ResponseWriter, req *http.Request) error {
	code := req.FormValue("code")
	if code == "" {
		return ErrEmptyAuthCode
	}

	tok, err := oauthConfig.Exchange(context.TODO(), code)
	if err != nil {
		return err
	}

	session, _ := store.Get(req, SessionName)
	v, ok := session.Values["resource_uri"]
	if !ok {
		return ErrInvalidResourceURI
	}
	resourceURI, ok := v.(string)
	if !ok {
		return ErrInvalidResourceURI
	}

	resourceURL, err := url.Parse(resourceURI)
	if err != nil {
		return err
	}

	session.Values["access_token"] = tok
	session.Save(req, w)

	http.Redirect(w, req, resourceURL.String(), http.StatusFound)
	return nil
}

func ClientLogoutHandler(w http.ResponseWriter, req *http.Request) error {
	redirectURI := req.FormValue("redirect_uri")

	session, _ := store.Get(req, SessionName)
	session.Values["access_token"] = nil
	session.Save(req, w)

	if redirectURI != "" {
		redirectURL, err := url.Parse(redirectURI)
		if err != nil {
			return err
		}

		http.Redirect(w, req, redirectURL.String(), http.StatusFound)
	}

	return nil
}

func ClientSecretHandler(w http.ResponseWriter, req *http.Request) error {
	session, _ := store.Get(req, SessionName)

	session.Values["resource_uri"] = req.RequestURI
	session.Save(req, w)

	v, ok := session.Values["access_token"]
	if ok {
		if token, ok := v.(*oauth2.Token); ok {
			client := oauthConfig.Client(context.TODO(), token)
			resp, err := client.Get("http://localhost:8080/resource/secret")
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			buf := &bytes.Buffer{}
			io.Copy(buf, resp.Body)

			var data = struct {
				Secret      string
				RedirectURI string
			}{
				Secret:      buf.String(),
				RedirectURI: req.RequestURI,
			}

			return clientSecretTempl.Execute(w, &data)
		}
	}

	authCodeOptions := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("redirect_uri", "/client/callback"),
	}

	// Redirect to /resource/oauth2/authorize
	http.Redirect(w, req, oauthConfig.AuthCodeURL(config.AuthorizeState, authCodeOptions...), http.StatusFound)
	return nil
}

var clientSecretTempl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html>
  <head>
    <title>Client Secret</title>

    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
  </head>
  <body class="container-fluid">
    <div class="row">
      <div class="col-xs-4 col-xs-offset-4">
        {{.Secret}}
        <form method="GET" action="/client/logout">
          <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}" />
          <button type="submit" class="btn btn-default">Logout</button>
        </form>
      </div>
    </div>
  </body>
</html>
`))

func dump(v interface{}) {
	spew.Dump(v)
}
