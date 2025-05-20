package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	sloghttp "github.com/samber/slog-http"
)

type Server struct {
	apiKey []byte
	keys   *ttlcache.Cache[string, struct{}]
	ca     *x509.CertPool
	logger *slog.Logger
}

type Option func(*Server)

func WithAPIKey(key string) Option {
	return func(s *Server) {
		s.apiKey = []byte("Bearer " + key)
	}
}

func WithCARoot(pool *x509.CertPool) Option {
	return func(s *Server) {
		s.ca = pool
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
			// FIXME:: reduce time
			ttlcache.WithTTL[string, struct{}](30*time.Minute),
			ttlcache.WithDisableTouchOnHit[string, struct{}](),
		),
	}
	for _, opt := range opts {
		opt(s)
	}

	// FIXME: remove
	s.keys.Set("acme", struct{}{}, ttlcache.NoTTL)

	go s.keys.Start()

	return s
}

func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/key", s.CreateKey)
	mux.HandleFunc("/acme/{KEY}/", s.AuthProxy)

	return sloghttp.New(s.logger)(mux)
}

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

// AuthProxy proxies the requests to smallsteps ACME provider, rewriting URLs to require a dynamic key
func (s *Server) AuthProxy(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("KEY")
	sloghttp.AddCustomAttributes(r, slog.String("key", key))

	if !s.keys.Has(key) {
		sloghttp.AddCustomAttributes(r, slog.String("error", "unknown key"))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// override CA used for smallstep since it's its own CA
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		ServerName: "smallstep.smallstep",
		RootCAs:    s.ca,
	}

	// use internal service IP for smallstep while retaining Host header
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "smallstep.smallstep:443")
	}

	// buffer request body
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, r.Body); err != nil {
		fmt.Println("could not read in body:", err)
		return
	}

	b := buf.Bytes()
	fmt.Println("request:", string(b))

	r.Body = io.NopCloser(bytes.NewBuffer(b))

	proxy := httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// rewrite incoming URLs https://<host>/acme/key/... -> https://smallstep.smallstep/acme/acme/...
			r.Out.URL.Scheme = "https"
			r.Out.URL.Host = "smallstep.smallstep"
			r.Out.URL.Path = strings.Replace(r.Out.URL.Path, fmt.Sprintf("/acme/%s/", key), "/acme/acme/", 1)
		},
		Transport: transport,
		ModifyResponse: func(r *http.Response) error {
			b := r.Body
			defer b.Close()

			buf := new(bytes.Buffer)
			if _, err := io.Copy(buf, r.Body); err != nil {
				return fmt.Errorf("could not read response body: %w", err)
			}

			// rewrite URLs in response
			replaced := bytes.ReplaceAll(buf.Bytes(),
				[]byte("\"https://mycoolmdm.stream/acme/acme/"),
				[]byte(fmt.Sprintf("\"https://mycoolmdm.stream/acme/%s/", key)),
			)

			fmt.Println("response:", string(replaced))
			r.Body = io.NopCloser(bytes.NewBuffer(replaced))
			return nil
		},
	}

	proxy.ServeHTTP(w, r)
}

func run() error {
	fmt.Println("creating pool")
	pool := x509.NewCertPool()
	caPath := os.Getenv("CA_PATH")
	buf, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("could not read CA %s: %w", caPath, err)
	}

	if ok := pool.AppendCertsFromPEM(buf); !ok {
		return fmt.Errorf("could not add %s to pool", caPath)
	}

	fmt.Println("creating server")
	s := NewServer(
		WithAPIKey(os.Getenv("API_KEY")),
		WithCARoot(pool),
		WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil))),
	)

	fmt.Println("listening on :8080")
	return http.ListenAndServe(":8080", s.Router())
}

func main() {
	fmt.Println("starting server")
	if err := run(); err != nil {
		log.Fatalln("error:", err)
	}
}
