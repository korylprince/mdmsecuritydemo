package webauthn

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

func init() {
	gob.Register(&webauthn.SessionData{})
}

type User struct {
	ID          string                         `json:"id"`
	Name        string                         `json:"name"`
	DisplayName string                         `json:"display_name"`
	Password    string                         `json:"password"` 
	Credentials map[string]webauthn.Credential `json:"credentials"`
}

func (u *User) WebAuthnID() []byte {
	return []byte(u.ID)
}

func (u *User) WebAuthnName() string {
	return u.Name
}

func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	creds := slices.Collect(maps.Values(u.Credentials))
	slices.SortFunc(creds, func(a, b webauthn.Credential) int {
		return strings.Compare(string(a.ID), string(b.ID))
	})
	return creds
}

type UserStore interface {
	GetUser(id string) (*User, error)
	SaveUser(user *User) error
}

type FileUserStore struct {
	root *os.Root
}

func NewFileUserStore(root string) (*FileUserStore, error) {
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, fmt.Errorf("could not create %s: %w", root, err)
	}

	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("could not open root %s: %w", root, err)
	}

	return &FileUserStore{root: r}, nil
}

func (s *FileUserStore) GetUser(id string) (user *User, err error) {
	path := id + ".json"
	fullpath := filepath.Join(s.root.Name(), path)
	f, err := s.root.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("could not open %s: %w", fullpath, err)
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("could not close %s: %w", fullpath, closeErr)
		}
	}()

	user = new(User)
	if err := json.NewDecoder(f).Decode(user); err != nil {
		return nil, fmt.Errorf("could not decode user from %s: %w", fullpath, err)
	}

	if user.Credentials == nil {
		user.Credentials = make(map[string]webauthn.Credential)
	}

	return user, nil
}

func (s *FileUserStore) SaveUser(user *User) (err error) {
	path := user.ID + ".json"
	fullpath := filepath.Join(s.root.Name(), path)
	f, err := s.root.Create(path)
	if err != nil {
		return fmt.Errorf("could not open %s: %w", fullpath, err)
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("could not close %s: %w", fullpath, closeErr)
		}
	}()

	if err := json.NewEncoder(f).Encode(user); err != nil {
		return fmt.Errorf("could not encode user to %s: %w", fullpath, err)
	}

	return nil
}

func (s *FileUserStore) Close() error {
	return s.root.Close()
}
