package netproxy

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestSingleSessionFailureEpisodesSurviveConnecting(t *testing.T) {
	for _, logical := range []bool{false, true} {
		for _, intermediate := range []SessionState{SessionConnecting, SessionDisconnected} {
			t.Run(fmt.Sprintf("logical=%t/intermediate=%v", logical, intermediate), func(t *testing.T) {
				session := NewSingleSession(SingleSessionConfig[int]{
					LogicalChannel: logical,
					Establish:      func(context.Context) (int, error) { return 1, nil },
					Close:          func(int) error { return nil },
				})
				defer session.Close()
				if err := session.Connect(context.Background()); err != nil {
					t.Fatal(err)
				}
				handle, _ := session.CurrentHandle()
				publisher := session.Snapshot().PublisherID
				for cycle := uint64(1); cycle <= 3; cycle++ {
					handle.Transition(intermediate, nil)
					if got := session.Snapshot().EpisodeID; got != cycle-1 {
						t.Fatalf("connecting alone opened an accident: %d", got)
					}
					handle.Transition(SessionDisconnected, errors.New("transport failure"))
					failed := session.Snapshot()
					if failed.EpisodeID != cycle || failed.PublisherID != publisher || failed.Accepting {
						t.Fatalf("cycle %d failure = %+v", cycle, failed)
					}
					if logical && failed.Resource != (ResourceRef{}) {
						t.Fatal("logical channel fabricated a physical connection identity")
					}
					handle.Transition(SessionConnecting, nil)
					handle.Transition(SessionDisconnected, errors.New("retry failed"))
					if got := session.Snapshot().EpisodeID; got != cycle {
						t.Fatalf("retry created a new accident: %d", got)
					}
					handle.Transition(SessionConnected, nil)
					if !session.Snapshot().Accepting {
						t.Fatal("recovered resource was not made ready")
					}
				}
			})
		}
	}
}

func TestSingleSessionInitialRetriesShareFailureEpisode(t *testing.T) {
	attempt := 0
	session := NewSingleSession(SingleSessionConfig[int]{
		LogicalChannel: true,
		Establish: func(context.Context) (int, error) {
			attempt++
			if attempt < 3 {
				return 0, errors.New("initial connection failed")
			}
			return 1, nil
		},
		Close: func(int) error { return nil },
	})
	defer session.Close()
	for i := 0; i < 2; i++ {
		if err := session.Connect(context.Background()); err == nil {
			t.Fatal("expected failed connection attempt")
		}
		if got := session.Snapshot().EpisodeID; got != 1 {
			t.Fatalf("initial retries changed accident identity: %d", got)
		}
	}
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	handle, _ := session.CurrentHandle()
	handle.Transition(SessionConnecting, nil)
	handle.Transition(SessionDisconnected, errors.New("new resource failure"))
	if got := session.Snapshot().EpisodeID; got != 2 {
		t.Fatalf("failure after successful recovery reused old accident: %d", got)
	}
}
