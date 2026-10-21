// SPDX-License-Identifier: AGPL-3.0-only

package happyeyeballs

import (
	"context"
	"errors"
	"iter"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestRaceStaggersAllAddressesAndClosesLateWinner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var attempts []int
		var starts []time.Time
		discarded := make(chan int, 1)
		winner, err := Race(t.Context(), func(context.Context) iter.Seq2[int, error] {
			return func(yield func(int, error) bool) {
				for _, address := range []int{6, 4, 66} {
					if !yield(address, nil) {
						return
					}
				}
			}
		}, func(ctx context.Context, address int) (int, error) {
			mu.Lock()
			attempts = append(attempts, address)
			starts = append(starts, time.Now())
			mu.Unlock()
			switch address {
			case 6:
				<-ctx.Done()
				// A dial can complete successfully just as it is canceled.
				return address, nil
			case 4:
				return 0, errors.New("refused")
			default:
				return address, nil
			}
		}, func(address int) { discarded <- address })
		if err != nil || winner != 66 {
			t.Fatalf("winner=%d err=%v", winner, err)
		}
		if got := <-discarded; got != 6 {
			t.Fatalf("discarded=%d", got)
		}
		if !slices.Equal(attempts, []int{6, 4, 66}) || starts[1].Sub(starts[0]) != attemptDelay || starts[2].Sub(starts[1]) < minimumDelay {
			t.Fatalf("attempts=%v starts=%v", attempts, starts)
		}
	})
}

func TestRaceCancellationAndSourceRejection(t *testing.T) {
	for _, reject := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			timeout := 100 * time.Millisecond
			if reject {
				timeout = time.Second
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			denied := errors.New("blocked by routing")
			started := make(chan struct{})
			stopped := make(chan struct{})
			_, err := Race(ctx, func(ctx context.Context) iter.Seq2[int, error] {
				return func(yield func(int, error) bool) {
					if !yield(6, nil) {
						return
					}
					<-started
					if reject {
						yield(0, denied)
					} else {
						<-ctx.Done()
					}
				}
			}, func(ctx context.Context, _ int) (int, error) {
				close(started)
				<-ctx.Done()
				close(stopped)
				return 0, ctx.Err()
			}, nil)
			want := error(context.DeadlineExceeded)
			if reject {
				want = denied
			}
			if !errors.Is(err, want) {
				t.Fatalf("error=%v want=%v", err, want)
			}
			<-stopped
		})
	}
}
