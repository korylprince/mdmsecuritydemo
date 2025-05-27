package machineinfo

import (
	"context"
	"encoding/gob"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/korylprince/dep-webview-oidc/header"
	sloghttp "github.com/samber/slog-http"
)

type contextKey struct{}

var sessionKeyMachineInfo = contextKey{}

func init() {
	gob.Register(sessionKeyMachineInfo)
	gob.Register(&header.MachineInfo{})
}

type MachineInfo header.MachineInfo

func (m *MachineInfo) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("origin", string(m.Origin)),
		slog.Bool("mdm_can_request_software_update", m.MDMCanRequestSoftwareUpdate),
		slog.String("os_version", m.OSVersion),
		slog.String("product", m.Product),
		slog.String("serial", m.Serial),
		slog.String("supplemental_build_version", m.SupplementalBuildVersion),
		slog.String("supplemental_os_version_extra", m.SupplementalOSVersionExtra),
		slog.String("udid", m.UDID),
		slog.String("version", m.Version),
	)
}

// SetMachineInfoSession parses MachineInfo data from the header or body and sets it in the request context and session cookie
func SetMachineInfoSession(store sessions.Store, allowMissing bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// parse machine info
		info, err := header.DefaultParser.Parse(r)
		if err != nil {
			if allowMissing {
				info = new(header.MachineInfo)
			} else {
				sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not parse machineinfo: %v", err)))
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
		}
		sloghttp.AddCustomAttributes(r, slog.Any("machine_info", (*MachineInfo)(info)))

		session, err := sessions.GetRegistry(r).Get(store, "machine_info")
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("warning", fmt.Sprintf("could not get session: %v", err)))
		}

		session.Values[sessionKeyMachineInfo] = info
		if err := session.Save(r, w); err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not save session cookie: %v", err)))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ctx := context.WithValue(r.Context(), sessionKeyMachineInfo, info)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// WithMachineInfoSession requires that the machineinfo data is set in the session cookie, and copies it to the request session
func WithMachineInfoSession(store sessions.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := sessions.GetRegistry(r).Get(store, "machine_info")
		if err != nil {
			sloghttp.AddCustomAttributes(r, slog.String("error", fmt.Sprintf("could not get session: %v", err)))
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		info, ok := session.Values[sessionKeyMachineInfo].(*header.MachineInfo)
		if !ok {
			sloghttp.AddCustomAttributes(r, slog.String("error", "missing machine_info"))
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		sloghttp.AddCustomAttributes(r, slog.Any("machine_info", (*MachineInfo)(info)))

		ctx := context.WithValue(r.Context(), sessionKeyMachineInfo, info)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FromContext returns the machineinfo set on the context. This should only be called from requests wrapped with WithMachineInfoSession
func FromContext(ctx context.Context) *header.MachineInfo {
	return ctx.Value(sessionKeyMachineInfo).(*header.MachineInfo)
}
