package access

import (
	"net/http"
)

func (p *Provider) HealthZ(w http.ResponseWriter, r *http.Request) {
	probe := r.URL.Query().Get("probe")
	switch probe {
	case "readiness":
		// check to see that the pod is currently able to accept requests
		// TODO check connectivity or something
	case "liveness":
		// TODO check to see that the pod probably doesn't need to be removed yet
	}
	w.WriteHeader(http.StatusNoContent)
}
