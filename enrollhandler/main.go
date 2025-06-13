package main

import (
	"bytes"
	"crypto/subtle"
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

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/korylprince/mdmsecuritydemo/enrollhandler/webauthn"
	sloghttp "github.com/samber/slog-http"
	"golang.org/x/crypto/argon2"
)

//go:embed static/*
var staticContent embed.FS

//go:embed tmpls/index.html.tmpl
var startTmplContent string

var startTmpl = template.Must(template.New("").Parse(startTmplContent))

//go:embed tmpls/register.html.tmpl
var registerTmplContent string
var registerTmpl = template.Must(template.New("").Parse(registerTmplContent))

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

	deviceInventoryAPIKey string

	dynamicAPIURL string
	dynamicAPIKey string
	caPool        *x509.CertPool

	mdmURL        string
	apnsTopic     string
	acmeDirectory string

	requiredVersion *version.Version

	userStore webauthn.UserStore
	webAuthn  *webauthn.WebAuthn

	anonSerial bool

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

func WithDeviceInventoryAPIKey(key string) Option {
	return func(s *Server) {
		s.deviceInventoryAPIKey = key
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

func WithUserStore(store webauthn.UserStore) Option {
	return func(s *Server) {
		s.userStore = store
	}
}

func WithWebAuthn(webAuthn *webauthn.WebAuthn) Option {
	return func(s *Server) {
		s.webAuthn = webAuthn
	}
}

func WithAnonymizeSerial(anon bool) Option {
	return func(s *Server) {
		s.anonSerial = anon
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

	// handle webauthn API endpoints
	mux.Handle("/users/", s.webAuthn.Router())

	// handle webauthn registration - account creation
	mux.Handle("GET /register", s.RegisterHandler())

	// entrypoint to enrollment, require machineinfo header
	mux.Handle("GET /mdm/enroll", machineinfo.SetMachineInfoSession(s.sessionStore, s.allowNoMachineInfo, s.StartHandler()))

	// entrypoint to for basic auth enrollment, require machineinfo header
	mux.Handle("POST /mdm/enroll/basic", machineinfo.SetMachineInfoSession(s.sessionStore, s.allowNoMachineInfo, s.BasicHandler()))

	// enrollment profile handler
	mux.Handle("GET /mdm/enroll/finish", machineinfo.WithMachineInfoSession(s.sessionStore, s.EnrollHandler()))

	// other static files if needed
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler))

	return sloghttp.New(s.logger)(mux), nil
}

// StartHandler:
// - verifies the device is in inventory
// - verifies the OS version meets the required version
//   - if not and the device is in Setup Assistant, return an error to force an update
//
// - Shows the login UI
func (s *Server) StartHandler() http.Handler {
	type tmpl struct {
		MachineInfo *header.MachineInfo
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get machine info from cookie
		info := machineinfo.FromContext(r.Context())

		// check inventory
		req, err := http.NewRequest(http.MethodPost,
			"http://deviceinventory.deviceinventory/devices/query",
			bytes.NewBufferString(fmt.Sprintf(`{"serial_number": "%s", "udid": "%s"}`, info.Serial, info.UDID)),
		)
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not create inventory request: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		req.Header.Set("Authorization", "Bearer "+s.deviceInventoryAPIKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not check inventory: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		sloghttp.AddCustomAttributes(r, slog.Bool("device_in_inventory", resp.StatusCode == http.StatusOK))

		if resp.StatusCode != http.StatusOK && !s.allowNoMachineInfo {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		// check for software update requirements
		softwareUpdateRequired, err := s.softwareUpdateCheck(r, info, s.requiredVersion)
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not check for software update requirements: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// trigger software update if required
		if softwareUpdateRequired != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden) // 403
			if err := json.NewEncoder(w).Encode(softwareUpdateRequired); err != nil {
				sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not encode OSUpdateRequired response: %v", err)))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			return
		}

		// render main html
		if info.Serial != "" && s.anonSerial {
			info.Serial = "DCBA1234EF"
		}
		w.Header().Set("Content-Type", "text/html")
		if err := startTmpl.Execute(w, &tmpl{MachineInfo: info}); err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not render template: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	})
}

// BasicHandler implements a basic auth enrollment profile handler that:
// - verifies the device is in inventory
// - verifies user credentials (username, password) against the user store
// - Returns an enrollment profile
//
// This handler demonstrates user auth if using a DEP profiles's `url` key, not `configuration_web_url`
func (s *Server) BasicHandler() http.Handler {
	type tmpl struct {
		MachineInfo *header.MachineInfo
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get machine info from cookie
		info := machineinfo.FromContext(r.Context())

		// check inventory
		req, err := http.NewRequest(http.MethodPost,
			"http://deviceinventory.deviceinventory/devices/query",
			bytes.NewBufferString(fmt.Sprintf(`{"serial_number": "%s", "udid": "%s"}`, info.Serial, info.UDID)),
		)
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not create inventory request: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		req.Header.Set("Authorization", "Bearer "+s.deviceInventoryAPIKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not check inventory: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		sloghttp.AddCustomAttributes(r, slog.Bool("device_in_inventory", resp.StatusCode == http.StatusOK))

		if resp.StatusCode != http.StatusOK && !s.allowNoMachineInfo {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		// check for basic auth credentials
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Please sign in"`)
			http.Error(w, "Please sign in", http.StatusUnauthorized)
			return
		}

		user, err := s.userStore.GetUser(username)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="Please sign in"`)
			http.Error(w, "Please sign in", http.StatusUnauthorized)
			return
		}

		if subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Please sign in"`)
			http.Error(w, "Please sign in", http.StatusUnauthorized)
			return
		}

		// return profile
		s.EnrollHandler().ServeHTTP(w, r)
	})
}

// RegisterHandler renders the user registration UI
func (s *Server) RegisterHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")

		// temporary response for now
		w.Header().Set("Content-Type", "text/html")
		if err := registerTmpl.Execute(w, nil); err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not render template: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	})
}

// EnrollHandler:
// - gets a dynamic acme key for the UDID
// - returns an enrollment profile with ACME and MDM payloads
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
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
			fmt.Sprintf("%s/%s", s.dynamicAPIURL, info.UDID),
			http.NoBody,
		)
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

// OSUpdateRequired is the error returned to force an update in Setup Assistant
// See softwareUpdateCheck for more details
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
// documented here: https://github.com/apple/device-management/blob/release/mdm/errors/softwareupdate.required.yaml
// and here: https://developer.apple.com/documentation/devicemanagement/errorcodesoftwareupdaterequired
func (s *Server) softwareUpdateCheck(r *http.Request, info *header.MachineInfo, requiredVersion *version.Version) (*OSUpdateRequired, error) {
	var osUpdateRequired bool
	defer func() {
		sloghttp.AddCustomAttributes(r, slog.Any("os_update_required", osUpdateRequired))
	}()

	if !info.MDMCanRequestSoftwareUpdate || requiredVersion == nil {
		return nil, nil // no software update check needed
	}

	ver, err := version.NewVersion(info.OSVersion)
	if err != nil {
		sloghttp.AddCustomAttributes(r, slog.String("version_parse_error", err.Error()))
		return nil, fmt.Errorf("could not parse OS version: %w", err)
	}

	// check version meets requirements
	if ver.GreaterThanOrEqual(requiredVersion) {
		return nil, nil // no software update needed
	}

	// otherwise return an error to force the update
	osUpdateRequired = true

	OSUpdateRequired := &OSUpdateRequired{
		Code:        "com.apple.softwareupdate.required",
		Description: "Device requires a software update before enrollment.",
		Message:     "A software update is required to continue.",
		Details: &ErrorDetails{
			OSVersion: s.requiredVersion.Original(),
		},
	}

	return OSUpdateRequired, nil
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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	userStore, err := webauthn.NewFileUserStore(os.Getenv("USER_STORAGE"))
	if err != nil {
		return fmt.Errorf("could not create user store: %w", err)
	}
	// Set up WebAuthn config
	waConfig := &gowebauthn.Config{
		RPDisplayName: "My Cool MDM",                        // Display name for your app
		RPID:          "mycoolmdm.stream",                   // Your domain
		RPOrigins:     []string{"https://mycoolmdm.stream"}, // Your origin
	}

	// Build the WebAuthn handler
	wa, err := webauthn.New(
		webauthn.WithConfig(waConfig),
		webauthn.WithStore(userStore),
		webauthn.WithSessionKeys(sessionAuthKey, sessionEncKey),
		webauthn.WithLogger(logger),
	)
	if err != nil {
		return fmt.Errorf("could not create webauthn handler: %w", err)
	}

	opts := []Option{
		WithSessionKeys(sessionAuthKey, sessionEncKey),
		WithAllowNoMachineInfo(os.Getenv("ALLOW_NO_MACHINEINFO") == "true"),
		WithDeviceInventoryAPIKey(os.Getenv("DEVICE_INVENTORY_API_KEY")),
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
		WithUserStore(userStore),
		WithWebAuthn(wa),
		WithAnonymizeSerial(os.Getenv("ANONYMIZE_SERIAL") == "true"),
		WithLogger(logger),
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
		log.Fatalf("error: %v", err)
	}
}
