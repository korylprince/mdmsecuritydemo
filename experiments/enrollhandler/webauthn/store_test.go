package webauthn_test

import (
	"os"
	"test/webauthn"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser(t *testing.T) {
	user := &webauthn.User{
		ID:          "id",
		Name:        "name",
		DisplayName: "display_name",
		Credentials: map[string]gowebauthn.Credential{
			"2": gowebauthn.Credential{ID: []byte("2")},
			"1": gowebauthn.Credential{ID: []byte("1")},
		},
	}

	assert.Equal(t, []byte(user.ID), user.WebAuthnID(), "WebAuthID not equal")
	assert.Equal(t, user.Name, user.WebAuthnName(), "WebAuthnName not equal")
	assert.Equal(t, user.DisplayName, user.WebAuthnDisplayName(), "WebAuthnDisplayName not equal")
	assert.Equal(t, []gowebauthn.Credential{
		user.Credentials["1"],
		user.Credentials["2"],
	}, user.WebAuthnCredentials(), "WebAuthnCredentials not equal")
}

func TestFileUserStore(t *testing.T) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "")
	require.NoError(t, err, "could not create temp directory")

	defer func() {
		require.NoError(t, os.RemoveAll(tempDir), "could not remove temp directory")
	}()

	store, err := webauthn.NewFileUserStore(tempDir)
	require.NoError(t, err, "could not create store")

	user := &webauthn.User{
		ID:          "id",
		Name:        "name",
		DisplayName: "display_name",
		Credentials: map[string]gowebauthn.Credential{
			"id": gowebauthn.Credential{
				ID:              []byte("id"),
				PublicKey:       []byte("public_key"),
				AttestationType: "type",
				Transport: []protocol.AuthenticatorTransport{
					protocol.USB,
					protocol.Hybrid,
				},
				Flags: gowebauthn.CredentialFlags{
					UserPresent: true,
				},
				Authenticator: gowebauthn.Authenticator{
					AAGUID: []byte("id"),
				},
				Attestation: gowebauthn.CredentialAttestation{
					ClientDataJSON: []byte("json"),
				},
			},
		},
	}

	err = store.SaveUser(user)
	require.NoError(t, err, "could not save user")

	user2, err := store.GetUser(user.ID)
	require.NoError(t, err, "could not get user")

	assert.Equal(t, user, user2, "user different than expected")
}
