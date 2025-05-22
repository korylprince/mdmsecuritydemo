package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"text/template"

	_ "embed"

	"github.com/korylprince/dep-webview-oidc/header"
	sloghttp "github.com/samber/slog-http"
)

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
		slog.Group("machine_info",
			slog.String("origin", string(e.MachineInfo.Origin)),
			slog.Bool("mdm_can_request_software_update", e.MachineInfo.MDMCanRequestSoftwareUpdate),
			slog.String("os_version", e.MachineInfo.OSVersion),
			slog.String("product", e.MachineInfo.Product),
			slog.String("serial", e.MachineInfo.Serial),
			slog.String("supplemental_build_version", e.MachineInfo.SupplementalBuildVersion),
			slog.String("supplemental_os_version_extra", e.MachineInfo.SupplementalOSVersionExtra),
			slog.String("udid", e.MachineInfo.UDID),
			slog.String("version", e.MachineInfo.Version),
		),
	)
}

//go:embed enroll.mobileconfig
var enrollProfile string

var enrollProfileTmpl = template.Must(template.New("").Parse(enrollProfile))

type Server struct {
	allowNoMachineInfo bool
	dynamicAPIURL      string
	dynamicAPIKey      string
	caPool             *x509.CertPool
	mdmURL             string
	apnsTopic          string
	acmeDirectory      string
	logger             *slog.Logger
}

type Option func(*Server)

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

func (s *Server) EnrollHandler() http.Handler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs: s.caPool,
	}
	client := &http.Client{Transport: transport}
	return sloghttp.New(s.logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// parse machine info
		info, err := header.DefaultParser.Parse(r)
		if err != nil {
			if s.allowNoMachineInfo {
				info = new(header.MachineInfo)
			} else {
				sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not parse machineinfo: %v", err)))
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
		}

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
	}))
}

func run() error {
	caPath := os.Getenv("CA_PATH")
	buf, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("could not read CA from %s: %w", caPath, err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(buf)

	s := NewServer(
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
	)

	fmt.Println("listening on :8080")
	return http.ListenAndServe(":8080", s.EnrollHandler())
}

func main() {
	fmt.Println("starting server")
	if err := run(); err != nil {
		log.Fatalf("error:", err)
	}
}
