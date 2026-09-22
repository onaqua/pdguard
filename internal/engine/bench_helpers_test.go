package engine

import (
	"pdguard/internal/config"
	"pdguard/internal/store"
)

func loadDefault() (*config.Manager, error) { return config.Load("") }
func newEngB(m *config.Manager) *Engine {
	return New(Options{Cfg: m, Store: store.New(store.Config{SweepInterval: -1})})
}
