package directory

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Registry is an HTTP server where relays announce themselves (POST /register)
// and clients list them (GET /nodes). It is in-memory and unauthenticated: a
// real deployment would verify relay signatures and serve a signed consensus so
// clients cannot be fed a poisoned node set.
type Registry struct {
	mu    sync.RWMutex
	nodes map[string]Node // keyed by Addr
}

func NewRegistry() *Registry { return &Registry{nodes: map[string]Node{}} }

// Handler returns the registry's HTTP routes.
func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", r.register)
	mux.HandleFunc("GET /nodes", r.list)
	return mux
}

func (r *Registry) register(w http.ResponseWriter, req *http.Request) {
	var n Node
	if err := json.NewDecoder(req.Body).Decode(&n); err != nil || n.Addr == "" || len(n.OnionKey) == 0 {
		http.Error(w, "bad descriptor", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.nodes[n.Addr] = n
	r.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (r *Registry) list(w http.ResponseWriter, _ *http.Request) {
	r.mu.RLock()
	out := make([]Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		out = append(out, n)
	}
	r.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
