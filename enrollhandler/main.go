package main

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	texttemplate "text/template"

	_ "embed"

	"github.com/gorilla/sessions"
	"github.com/hashicorp/go-version"
	"github.com/korylprince/dep-webview-oidc/header"
	"github.com/korylprince/mdmsecuritydemo/enrollhandler/machineinfo"
	sloghttp "github.com/samber/slog-http"
	"golang.org/x/crypto/argon2"
)

//go:embed static/*
var staticContent embed.FS

//go:embed tmpls/index.html.tmpl
var startTmplContent string

var startTmpl = template.Must(template.New("").Parse(startTmplContent))

type Enrollment struct {
	MDMURL        string
	APNSTopic     string
	ACMEDirectory string
	ACMEKey       string
	MachineInfo   *header.MachineInfo
}

func (e *Enrollment) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("mdm_url", e.MDMURL),
		slog.String("apns_topic", e.APNSTopic),
		slog.String("acme_directory", e.ACMEDirectory),
		slog.String("acme_key", e.ACMEKey),
	)
}

//go:embed enroll.mobileconfig
var enrollProfile string

var enrollProfileTmpl = texttemplate.Must(texttemplate.New("").Parse(enrollProfile))

type Server struct {
	sessionStore sessions.Store

	allowNoMachineInfo bool

	dynamicAPIURL string
	dynamicAPIKey string
	caPool        *x509.CertPool

	mdmURL        string
	apnsTopic     string
	acmeDirectory string

	requiredVersion *version.Version

	logger *slog.Logger
}

type Option func(*Server)

func WithSessionKeys(keyPairs ...[]byte) Option {
	return func(s *Server) {
		s.sessionStore = sessions.NewCookieStore(keyPairs...)
	}
}

func WithAllowNoMachineInfo(allow bool) Option {
	return func(s *Server) {
		s.allowNoMachineInfo = allow
	}
}

func WithDynamicAPI(url, key string) Option {
	return func(s *Server) {
		s.dynamicAPIURL = url
		s.dynamicAPIKey = "Bearer " + key
	}
}

func WithRootCAPool(pool *x509.CertPool) Option {
	return func(s *Server) {
		s.caPool = pool
	}
}

func WithMDMConfig(url, topic, directoryURL string) Option {
	return func(s *Server) {
		s.mdmURL = url
		s.apnsTopic = topic
		s.acmeDirectory = directoryURL
	}
}

func WithRequiredVersion(v *version.Version) Option {
	return func(s *Server) {
		s.requiredVersion = v
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

func NewServer(opts ...Option) *Server {
	s := &Server{}
	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *Server) Router() (http.Handler, error) {
	// set up static content handler
	staticFS, err := fs.Sub(staticContent, "static")
	if err != nil {
		return nil, fmt.Errorf("could not create static fs: %w", err)
	}
	staticHandler := http.FileServer(http.FS(staticFS))

	mux := http.NewServeMux()

	// entrypoint to enrollment, require machineinfo header
	mux.Handle("GET /mdm/enroll", machineinfo.SetMachineInfoSession(s.sessionStore, s.allowNoMachineInfo, s.StartHandler()))

	// handle login + webauthn flow
	mux.Handle("GET /mdm/enroll/login", machineinfo.WithMachineInfoSession(s.sessionStore, s.LoginHandler()))

	// handle forced software update
	mux.Handle("GET /mdm/enroll/update", machineinfo.WithMachineInfoSession(s.sessionStore, s.SoftwareUpdateHandler()))

	// enrollment profile handler
	mux.Handle("GET /mdm/enroll/finish", machineinfo.WithMachineInfoSession(s.sessionStore, s.EnrollHandler()))

	// other static files if needed
	mux.Handle("GET /mdm/enroll/static/", http.StripPrefix("/mdm/enroll/static/", staticHandler))

	return sloghttp.New(s.logger)(mux), nil
}

func (s *Server) StartHandler() http.Handler {
	type tmpl struct {
		MachineInfo *header.MachineInfo
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: make this nicer, add links to start all other flows, etc

		// get machine info from cookie
		info := machineinfo.FromContext(r.Context())

		w.Header().Set("Content-Type", "text/html")
		if err := startTmpl.Execute(w, &tmpl{MachineInfo: info}); err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not render template: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	})
}

func (s *Server) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: implement login + webauthn flow
		// See experiments/webview for webauthn example
	})
}

type OSUpdateRequired struct {
	// Code is always "com.apple.softwareupdate.required"
	Code string `json:"code"`
	// Description is used for logging purposes
	Description string `json:"description,omitempty"`
	// Message may be displayed to the user, but this doesn't seem to ever happen on macOS
	Message string        `json:"message,omitempty"`
	Details *ErrorDetails `json:"details"`
}

type ErrorDetails struct {
	OSVersion    string `json:"OSVersion"`
	BuildVersion string `json:"BuildVersion,omitempty"`
}

// SoftwareUpdateHandler checks if the macOS version meets the required version (if set) and
// forces a software update if not and the device is at setup assistant.
// Otherwise, redirect to the next parameter.
// documented here: https://github.com/apple/device-management/blob/release/mdm/errors/softwareupdate.required.yaml
// and here: https://developer.apple.com/documentation/devicemanagement/errorcodesoftwareupdaterequired
func (s *Server) SoftwareUpdateHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var osUpdateRequired bool
		defer sloghttp.AddCustomAttributes(r, slog.Any("os_update_required", osUpdateRequired))

		// get the handler to redirect to on success
		next := r.FormValue("next")
		if next == "" {
			next = "/mdm/enroll/finish"
		}
		sloghttp.AddCustomAttributes(r, slog.String("next", next))

		// get machine info from cookie
		info := machineinfo.FromContext(r.Context())

		// if we can't check the version, redirect
		if !info.MDMCanRequestSoftwareUpdate || s.requiredVersion == nil {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}

		ver, err := version.NewVersion(info.OSVersion)
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("version_parse_error", err.Error()))
			http.Redirect(w, r, next, http.StatusFound)
			return
		}

		// check version meets requirements
		if ver.GreaterThanOrEqual(s.requiredVersion) {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}

		// otherwise return an error to force the update
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden) // 403
		osUpdateRequired = true

		OSUpdateRequired := &OSUpdateRequired{
			Code:        "com.apple.softwareupdate.required",
			Description: "Device requires a software update before enrollment.",
			Message:     "A software update is required to continue.",
			Details: &ErrorDetails{
				OSVersion: s.requiredVersion.Original(),
			},
		}

		if err := json.NewEncoder(w).Encode(OSUpdateRequired); err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not encode OSUpdateRequired response: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	})
}

func (s *Server) EnrollHandler() http.Handler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs: s.caPool,
	}
	client := &http.Client{Transport: transport}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get machine info from cookie
		info := machineinfo.FromContext(r.Context())

		// get dynamic acme key
		type response struct {
			Key string `json:"key"`
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.dynamicAPIURL, http.NoBody)
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not create dynamic api request: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", s.dynamicAPIKey)

		resp, err := client.Do(req)
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not get dynamic key: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		key := new(response)
		if err := json.NewDecoder(resp.Body).Decode(key); err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not decode dynamic key response: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// render enrollment profile
		enrollment := &Enrollment{
			MDMURL:        s.mdmURL,
			APNSTopic:     s.apnsTopic,
			ACMEDirectory: s.acmeDirectory,
			ACMEKey:       key.Key,
			MachineInfo:   info,
		}
		sloghttp.AddCustomAttributes(r, slog.Any("enrollment", enrollment))
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		if err := enrollProfileTmpl.Execute(w, enrollment); err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not render enrollment profile: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	})
}

func run() error {
	caPath := os.Getenv("CA_PATH")
	buf, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("could not read CA from %s: %w", caPath, err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(buf)

	// use argon2 to stretch passwords to 32 bytes, the needed size for the session library
	// since we're starting from a secure password, we're not too worried about setting a random salt
	sessionAuthKey := argon2.IDKey([]byte(os.Getenv("SESSION_AUTH_KEY")), []byte("salt"), 1, 64*1024, 4, 32)
	sessionEncKey := argon2.IDKey([]byte(os.Getenv("SESSION_ENC_KEY")), []byte("salt"), 1, 64*1024, 4, 32)

	opts := []Option{
		WithSessionKeys(sessionAuthKey, sessionEncKey),
		WithAllowNoMachineInfo(os.Getenv("ALLOW_NO_MACHINEINFO") == "true"),
		WithDynamicAPI(
			os.Getenv("DYNAMIC_API_URL"),
			os.Getenv("DYNAMIC_API_KEY"),
		),
		WithRootCAPool(pool),
		WithMDMConfig(
			os.Getenv("MDM_URL"),
			os.Getenv("APNS_TOPIC"),
			os.Getenv("ACME_DIRECTORY"),
		),
		WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil))),
	}

	// this must be configured as the version string Apple uses for an OS version
	// i.e. 15.5, not 15.5.0
	if v := os.Getenv("REQUIRED_VERSION"); v != "" {
		ver, err := version.NewVersion(v)
		if err != nil {
			return fmt.Errorf("could not parse REQUIRED_VERSION: %w", err)
		}
		opts = append(opts, WithRequiredVersion(ver))
	}

	s := NewServer(opts...)

	router, err := s.Router()
	if err != nil {
		return err
	}

	fmt.Println("listening on :8080")
	return http.ListenAndServe(":8080", router)
}

func main() {
	fmt.Println("starting server")
	if err := run(); err != nil {
		log.Fatalf("error:", err)
	}
}
