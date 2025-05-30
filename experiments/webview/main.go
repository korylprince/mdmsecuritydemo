package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"

	_ "embed"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/korylprince/mdmsecuritydemo/webview/webauthn"
)

//go:embed static
var staticContent embed.FS

func run() error {
	// FIXME: read from env var
	store, err := webauthn.NewFileUserStore("/data")
	if err != nil {
		return fmt.Errorf("could not create store: %w", err)
	}
	defer store.Close()

	// FIXME: read from env var/secret
	authKey, err := webauthn.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("could not generate auth key: %w", err)
	}

	// FIXME: read from env var/secret
	encKey, err := webauthn.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("could not generate encryption key: %w", err)
	}

	// FIXME: read from env var
	config := &gowebauthn.Config{
		RPDisplayName: "Test",
		RPID:          "mycoolmdm.stream",
		RPOrigins:     []string{"https://mycoolmdm.stream"},
	}
	

	w, err := webauthn.New(
		webauthn.WithConfig(config),
		webauthn.WithStore(store),
		webauthn.WithSessionKeys(authKey, encKey),
		webauthn.WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil))),
	)
	if err != nil {
		return fmt.Errorf("could not create webauthn: %w", err)
	}

	http.Handle("/users/", w.Router())

	// set up static content handler
	staticFS, err := fs.Sub(staticContent, "static")
	if err != nil {
		return err
	}
	http.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(staticFS))))

	return http.ListenAndServe(":8080", nil)
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("error:", err)
	}
}
