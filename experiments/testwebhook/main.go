package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"

	sloghttp "github.com/samber/slog-http"
	"github.com/smallstep/certificates/webhook"
	"go.step.sm/crypto/x509util"
)

type Server struct {
	logger *slog.Logger
}

type Option func(*Server)

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

func (s *Server) Router() http.Handler {
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, r.Body); err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not copy body: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		fmt.Printf("header: %#v\n", r.Header)
		fmt.Println("request:", buf.String())

		req := new(webhook.RequestBody)
		err := json.Unmarshal(buf.Bytes(), req)
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not json unmarshal body: %v", err)))
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		fmt.Println("serial:", req.AttestationData.PermanentIdentifier)
		fmt.Println("unique id:", req.X509CertificateRequest.CertificateRequest.Subject.ExtraNames)

		var key any
		for _, id := range req.X509CertificateRequest.CertificateRequest.Subject.ExtraNames {
			if id.Type.Equal(x509util.ObjectIdentifier{2, 5, 4, 45}) {
				key = id.Value
			}
		}

		w.Header().Set("Content-Type", "application/json")

		if key == nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", "key not found"))
			w.Write([]byte(`{"allow": false, "data": {}}`))
			return
		}

		if s, ok := key.(string); !ok || s != "testkey" {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("invalid key: %v", key)))
			w.Write([]byte(`{"allow": false, "data": {}}`))
			return
		}

		w.Write([]byte(`{"allow": true, "data": {}}`))
	})

	return sloghttp.New(s.logger)(mux)
}

func run() error {
	fmt.Println("creating server")
	s := NewServer(
		WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil))),
	)

	fmt.Println("listening on :8080")
	return http.ListenAndServeTLS(":8080", "/data/tls.crt", "/data/tls.key", s.Router())
}

func main() {
	fmt.Println("starting server")
	if err := run(); err != nil {
		log.Fatalln("error:", err)
	}
}
