package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	sloghttp "github.com/samber/slog-http"
)

type Device struct {
	SerialNumber string `json:"serial_number"`
	UDID         string `json:"udid"`
}

type Inventory interface {
	DeviceExists(d *Device) (ok bool, err error)
}

// FileInventory is a very basic Inventory where device serial numbers or
// or udids are listed on separate lines
type FileInventory struct {
	path string
}

func (fi *FileInventory) DeviceExists(d *Device) (ok bool, err error) {
	f, err := os.Open(fi.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("could not open %q: %w", fi.path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		id := strings.TrimSpace(scanner.Text())
		if id == d.SerialNumber || id == d.UDID {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("could not read %q: %w", fi.path, err)
	}

	return false, nil
}

type Server struct {
	apiKey    []byte
	inventory Inventory
	logger    *slog.Logger
}

type Option func(*Server)

func WithAPIKey(key string) Option {
	return func(s *Server) {
		s.apiKey = []byte("Bearer " + key)
	}
}

func WithInventoryPath(path string) Option {
	return func(s *Server) {
		s.inventory = &FileInventory{path: path}
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

func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /devices/query", s.DeviceExists)

	return sloghttp.New(s.logger)(mux)
}

func (s *Server) DeviceExists(w http.ResponseWriter, r *http.Request) {
	// check auth
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), s.apiKey) != 1 {
		sloghttp.AddCustomAttributes(r, slog.String("error", "incorrect webhook api key"))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// parse body to device ids
	dev := new(Device)
	if err := json.NewDecoder(r.Body).Decode(dev); err != nil {
		sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not json unmarshal body: %v", err)))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	sloghttp.AddCustomAttributes(r, slog.String("serial_number", dev.SerialNumber))
	sloghttp.AddCustomAttributes(r, slog.String("udid", dev.UDID))

	ok, err := s.inventory.DeviceExists(dev)
	if err != nil {
		sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not check device: %v", err)))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	sloghttp.AddCustomAttributes(r, slog.Bool("in_inventory", ok))

	if !ok {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func run() error {
	s := NewServer(
		WithAPIKey(os.Getenv("API_KEY")),
		WithInventoryPath(os.Getenv("INVENTORY_PATH")),
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
