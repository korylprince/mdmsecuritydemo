package webauthn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
	sloghttp "github.com/samber/slog-http"
)

const (
	registrationSessionKey = "registration"
	loginSessionKey        = "login"
)

type HTTPError struct {
	StatusCode int
	Err        error
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%d %s: %s", e.StatusCode, http.StatusText(e.StatusCode), e.Err.Error())
}

func (e *HTTPError) Unwrap() error {
	return e.Err
}

func GenerateKey(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Reader.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

type WebAuthn struct {
	config       *webauthn.Config
	webAuthn     *webauthn.WebAuthn
	sessionStore sessions.Store
	store        UserStore
	logger       *slog.Logger
}

type Option func(w *WebAuthn)

func WithConfig(config *webauthn.Config) Option {
	return func(w *WebAuthn) {
		w.config = config
	}
}

func WithStore(store UserStore) Option {
	return func(w *WebAuthn) {
		w.store = store
	}
}

func WithSessionKeys(keyPairs ...[]byte) Option {
	return func(w *WebAuthn) {
		w.sessionStore = sessions.NewCookieStore(keyPairs...)
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(w *WebAuthn) {
		w.logger = logger
	}
}

func New(opts ...Option) (*WebAuthn, error) {
	w := &WebAuthn{}

	for _, opt := range opts {
		opt(w)
	}

	webAuthn, err := webauthn.New(w.config)
	if err != nil {
		return nil, fmt.Errorf("could not create webauthn: %w", err)
	}
	w.webAuthn = webAuthn

	return w, nil
}

func (wa *WebAuthn) Router() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /users/{USERID}/registration", wa.handler(wa.BeginRegistration))
	mux.Handle("POST /users/{USERID}/registration", wa.handler(wa.FinishRegistration))
	mux.Handle("GET /users/{USERID}/login", wa.handler(wa.BeginLogin))
	mux.Handle("POST /users/{USERID}/login", wa.handler(wa.FinishLogin))

	return sloghttp.New(wa.logger)(mux)
}

type handlerFunc func(w http.ResponseWriter, r *http.Request) (any, error)

func (wa *WebAuthn) handler(f handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, err := f(w, r)
		if err != nil {
			httpErr := new(HTTPError)
			if errors.As(err, &httpErr) {
				sloghttp.AddCustomAttributes(r, slog.String("error", httpErr.Err.Error()))
				http.Error(w, http.StatusText(httpErr.StatusCode), httpErr.StatusCode)
			} else {
				sloghttp.AddCustomAttributes(r, slog.String("error", err.Error()))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		if v == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(v); err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("write_error", err.Error()))
		}
	})
}

func (wa *WebAuthn) BeginRegistration(wr http.ResponseWriter, r *http.Request) (any, error) {
	// read user ID from path
	id := r.PathValue("USERID")
	if len(id) == 0 {
		return nil, &HTTPError{StatusCode: http.StatusBadRequest, Err: errors.New("empty id")}
	}

	// build user from URL
	user := &User{
		ID:          id,
		Name:        r.FormValue("name"),
		DisplayName: r.FormValue("display_name"),
	}

	// get webauthn options and login session data
	options, sessionData, err := wa.webAuthn.BeginRegistration(user)
	if err != nil {
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not begin user registration: %w", err)}
	}

	// write session data to cookie
	session, err := sessions.GetRegistry(r).Get(wa.sessionStore, id)
	if err != nil {
		sloghttp.AddCustomAttributes(r, slog.String("warning", fmt.Sprintf("could not get session: %v", err)))
	}

	session.Values[registrationSessionKey] = sessionData
	if err := session.Save(r, wr); err != nil {
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not save session: %w", err)}
	}

	// save user
	if err := wa.store.SaveUser(user); err != nil {
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not save user: %w", err)}
	}

	return options, nil
}

func (wa *WebAuthn) FinishRegistration(wr http.ResponseWriter, r *http.Request) (any, error) {
	// read user ID from path
	id := r.PathValue("USERID")
	if len(id) == 0 {
		return nil, &HTTPError{StatusCode: http.StatusBadRequest, Err: errors.New("empty id")}
	}

	// get user from store
	user, err := wa.store.GetUser(id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, &HTTPError{StatusCode: http.StatusNotFound, Err: err}
		}
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not get user: %w", err)}
	}

	// get session data from cookie
	session, err := sessions.GetRegistry(r).Get(wa.sessionStore, id)
	if err != nil {
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not create session: %w", err)}
	}

	sessionData, ok := session.Values[registrationSessionKey].(*webauthn.SessionData)
	if !ok || sessionData == nil {
		return nil, &HTTPError{StatusCode: http.StatusBadRequest, Err: fmt.Errorf("could not retrieve session: %w", err)}
	}

	// verify registration
	credential, err := wa.webAuthn.FinishRegistration(user, *sessionData, r)
	if err != nil {
		return nil, &HTTPError{StatusCode: http.StatusBadRequest, Err: fmt.Errorf("could not finish registration: %w", err)}
	}

	// update credential on user
	user.Credentials[base64.RawURLEncoding.EncodeToString(credential.ID)] = *credential

	if err := wa.store.SaveUser(user); err != nil {
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not save user: %w", err)}
	}

	return nil, nil
}

func (wa *WebAuthn) BeginLogin(wr http.ResponseWriter, r *http.Request) (any, error) {
	// read user ID from path
	id := r.PathValue("USERID")
	if len(id) == 0 {
		return nil, &HTTPError{StatusCode: http.StatusBadRequest, Err: errors.New("empty id")}
	}

	// get user from store
	user, err := wa.store.GetUser(id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, &HTTPError{StatusCode: http.StatusNotFound, Err: err}
		}
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not get user: %w", err)}
	}

	// get webauthn options and login session data
	options, sessionData, err := wa.webAuthn.BeginLogin(user)
	if err != nil {
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not begin user login: %w", err)}
	}

	// write session data to cookie
	session, err := sessions.GetRegistry(r).Get(wa.sessionStore, id)
	if err != nil {
		sloghttp.AddCustomAttributes(r, slog.String("warning", fmt.Sprintf("could not get session: %v", err)))
	}

	session.Values[loginSessionKey] = sessionData
	if err := session.Save(r, wr); err != nil {
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not save session: %w", err)}
	}

	return options, nil
}

func (wa *WebAuthn) FinishLogin(wr http.ResponseWriter, r *http.Request) (any, error) {
	// read user ID from path
	id := r.PathValue("USERID")
	if len(id) == 0 {
		return nil, &HTTPError{StatusCode: http.StatusBadRequest, Err: errors.New("empty id")}
	}

	// get user from store
	user, err := wa.store.GetUser(id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, &HTTPError{StatusCode: http.StatusNotFound, Err: err}
		}
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not get user: %w", err)}
	}

	// get session data from cookie
	session, err := sessions.GetRegistry(r).Get(wa.sessionStore, id)
	if err != nil {
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not create session: %w", err)}
	}

	sessionData, ok := session.Values[loginSessionKey].(*webauthn.SessionData)
	if !ok || sessionData == nil {
		return nil, &HTTPError{StatusCode: http.StatusBadRequest, Err: fmt.Errorf("could not retrieve session: %w", err)}
	}

	// verify login
	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		return nil, &HTTPError{StatusCode: http.StatusBadRequest, Err: fmt.Errorf("could not parse login response: %w", err)}
	}

	credential, err := wa.webAuthn.ValidateLogin(user, *sessionData, parsedResponse)
	if err != nil {
		return nil, &HTTPError{StatusCode: http.StatusUnauthorized, Err: fmt.Errorf("could not validate credentials: %w", err)}
	}

	// update credential on user
	user.Credentials[base64.RawURLEncoding.EncodeToString(credential.ID)] = *credential

	if err := wa.store.SaveUser(user); err != nil {
		return nil, &HTTPError{StatusCode: http.StatusInternalServerError, Err: fmt.Errorf("could not save user: %w", err)}
	}

	return nil, nil
}
