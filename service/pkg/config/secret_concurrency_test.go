package config

import (
	"context"
	"sync"
	"testing"
)

func TestSecret_Resolve_Concurrent(t *testing.T) {
	t.Setenv("OPENTDF_CONCUR", "concur")
	s := NewEnvSecret("OPENTDF_CONCUR")

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	vals := make(chan string, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			v, err := s.Resolve(context.Background())
			if err != nil {
				errs <- err
				return
			}
			vals <- v
		}()
	}
	wg.Wait()
	close(errs)
	close(vals)
	if len(errs) > 0 {
		for e := range errs {
			t.Errorf("resolve error: %v", e)
		}
		t.FailNow()
	}
	for v := range vals {
		if v != "concur" {
			t.Fatalf("unexpected value: %q", v)
		}
	}
}
