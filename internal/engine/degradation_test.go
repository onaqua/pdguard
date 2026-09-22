package engine

import (
	"context"
	"testing"
	"time"

	"pdguard/internal/config"
	"pdguard/internal/store"
)

func newEng(t *testing.T) *Engine {
	t.Helper()
	m, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{Cfg: m, Store: store.New(store.Config{SweepInterval: -1})})
}

func TestDemaskAfterStoreLoss(t *testing.T) {
	e := newEng(t)
	ctx := context.Background()
	in := "Клиент Иванов Иван Иванович, телефон +7 (916) 123-45-67, карта 4276 1600 1234 5678, почта ivanov@mail.ru"
	r1, err := e.Process(ctx, "", "id1", in)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MASK : %q", r1.Output)

	// simulate TTL expiry / eviction / restart
	e.store.Delete("id1")

	r2, err := e.Process(ctx, "", "id1", r1.Output)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DEMASK after loss: %q", r2.Output)
	t.Logf("op=%s equalsPayload=%v", r2.Op, r2.Output == r1.Output)
}

func TestTimeoutOnReverseStep(t *testing.T) {
	e := newEng(t)
	in := "Иванов Иван Иванович, +7 916 123-45-67"
	r1, _ := e.Process(context.Background(), "", "id2", in)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	_, err := e.Process(ctx, "", "id2", r1.Output)
	t.Logf("reverse under expired ctx -> err=%v (handler fail-open would echo the MASK %q)", err, r1.Output)
}
