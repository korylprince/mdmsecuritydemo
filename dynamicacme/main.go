package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jellydator/ttlcache/v3"
	sloghttp "github.com/samber/slog-http"
	"github.com/smallstep/certificates/webhook"
	"go.step.sm/crypto/x509util"
)

// this is the OID for userPassword but really it's just an arbitrary ID
var uniqueIDOID = x509util.ObjectIdentifier{2, 5, 4, 35}

type Server struct {
	apiKey     []byte
	webhookKey []byte
	debugKey   string
	keys       *ttlcache.Cache[string, struct{}]
	logger     *slog.Logger
}

type Option func(*Server)

func WithAPIKey(key string) Option {
	return func(s *Server) {
		s.apiKey = []byte("Bearer " + key)
	}
}

func WithWebhookKey(key string) Option {
	return func(s *Server) {
		s.webhookKey = []byte("Bearer " + key)
	}
}

func WithDebugKey(key string) Option {
	return func(s *Server) {
		s.debugKey = key
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

func NewServer(opts ...Option) *Server {
	s := &Server{
		keys: ttlcache.New(
			ttlcache.WithTTL[string, struct{}](5*time.Minute),
			ttlcache.WithDisableTouchOnHit[string, struct{}](),
		),
	}
	for _, opt := range opts {
		opt(s)
	}

	go s.keys.Start()

	return s
}

func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/key", s.CreateKey)
	mux.HandleFunc("POST /webhook", s.AuthRequest)

	return sloghttp.New(s.logger)(mux)
}

// CreateKey generates a new key to be embedded in an ACME cert request.
// This key can only be used for one ACME cert request
func (s *Server) CreateKey(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), s.apiKey) != 1 {
		sloghttp.AddCustomAttributes(r, slog.String("error", "incorrect api key"))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	key := make([]byte, 32)
	if _, err := rand.Reader.Read(key); err != nil {
		sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not generate key: %v", err)))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	b64Key := base64.RawURLEncoding.EncodeToString(key)
	sloghttp.AddCustomAttributes(r, slog.String("key", b64Key))

	s.keys.Set(b64Key, struct{}{}, ttlcache.DefaultTTL)

	body := map[string]string{"key": b64Key}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(body); err != nil {
		sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not encode response: %v", err)))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// AuthRequest implements a smallstep step ca webhook to authorize a cert request
// based on the presense of a dynamic key (generated from CreateKey)
// https://smallstep.com/docs/step-ca/webhooks/
func (s *Server) AuthRequest(w http.ResponseWriter, r *http.Request) {
	// check auth
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), s.webhookKey) != 1 {
		sloghttp.AddCustomAttributes(r, slog.String("error", "incorrect webhook api key"))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// parse body to cert request
	req := new(webhook.RequestBody)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not json unmarshal body: %v", err)))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	sloghttp.AddCustomAttributes(r, slog.String("serial_number", req.AttestationData.PermanentIdentifier))

	// defer writing allow response
	allow := false
	defer func() {
		sloghttp.AddCustomAttributes(r, slog.Bool("allowed", allow))
		w.Write([]byte(fmt.Sprintf(`{"allow": %t, "data": {}}`, allow)))
	}()

	// locate unique ID
	var key any
	for _, id := range req.X509CertificateRequest.CertificateRequest.Subject.ExtraNames {
		if id.Type.Equal(uniqueIDOID) {
			key = id.Value
		}
	}

	sloghttp.AddCustomAttributes(r, slog.Any("key", key))

	w.Header().Set("Content-Type", "application/json")

	// check if key is valid
	if key == nil {
		sloghttp.AddCustomAttributes(r, slog.String("error", "key not found"))
		return
	}

	keyStr, ok := key.(string)
	if !ok || !s.keys.Has(keyStr) {
		// test debug key if it's set
		if s.debugKey != "" && keyStr == s.debugKey {
			allow = true
			return
		}
		sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("invalid key: %v", key)))
		return
	}

	// delete key to prevent reuse
	s.keys.Delete(keyStr)

	// allow cert request
	allow = true
}

func run() error {
	s := NewServer(
		WithAPIKey(os.Getenv("API_KEY")),
		WithWebhookKey(os.Getenv("WEBHOOK_KEY")),
		WithDebugKey(os.Getenv("DEBUG_KEY")),
		WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil))),
	)

	fmt.Println("listening on :443")
	return http.ListenAndServeTLS(":443",
		os.Getenv("TLS_CERT_PATH"),
		os.Getenv("TLS_KEY_PATH"),
		s.Router(),
	)
}

func main() {
	fmt.Println("starting server")
	if err := run(); err != nil {
		log.Fatalln("error:", err)
	}
}
