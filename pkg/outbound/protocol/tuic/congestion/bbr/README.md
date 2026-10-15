# QUIC BBRv3

The existing `bbr` selection and `UseBBR` now use BBRv3. This covers TUIC,
Juicity, and Hysteria2 when it selects BBR (including its automatic BBR
fallback). Existing configuration and peer protocol negotiation need no change.
`NewBbrSender` is a compatibility wrapper for `NewBBRv3Sender`.

## Algorithm reference

The controller follows the BBRv3 design in
[draft-ietf-ccwg-bbr-06, July 2026](https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html),
using the existing QUIC delivery-rate sampler:

- Startup (2.77 pacing gain, 2 cwnd gain), Drain (0.5 pacing gain).
- ProbeBW DOWN / CRUISE / REFILL / UP, with randomized 2–3 second probing
  and packet-count-based Reno coexistence, precautionary probes, and
  ACK-driven growth of the long-term inflight bound.
- A two-probe-cycle bandwidth maximum, loss-driven short-term bandwidth /
  inflight bounds, and a long-term inflight bound for excessive probing loss.
- A 10-second min-RTT filter and a 5-second ProbeRTT interval; ProbeRTT
  targets half a BDP (at least four datagrams), for 200 ms and a delivered round.
- Bounded ACK aggregation compensation and byte-based BDP arithmetic.
- Pacing at the pacing gain times the modeled bandwidth, with the 1% margin;
  the send quantum is 1 ms of pacing, bounded to 2 datagrams–64 KiB. The pacing
  budget can cover multiple quanta per timer wakeup at high rates, plus a partial
  datagram carried between wakeups. Initial cwnd remains 32 datagrams.

The specification is an experimental Internet-Draft, not a published RFC.
Algorithm-derived code is subject to the accompanying `LICENSE.bbr3`.

## Transport integration

`quic-go` normalizes the external `OnPacketSent` callback to report bytes in
flight **before** this packet. ACK and loss batches are consumed synchronously;
their borrowed slices are never retained. Each completed packet sample is
removed individually, so reordering does not discard outstanding samples.
The optional `OnPacketDiscarded` callback also retires samples when PTO, key
discard, Retry, or path migration removes packets without ACK/loss feedback;
these packets do not count as delivered bytes or congestion loss.

External controller packet IDs are monotonic transmission IDs across all QUIC
packet-number spaces, scoped to one controller installation. The ACK handler
keeps that identity with each sent packet. Feedback for packets sent before
installation uses `InvalidPacketNumber`: it still adjusts transport flight
accounting but cannot remove a newer packet's sample with the same wire number.
Discard callbacks supply the actual remaining flight size, including when an
old handshake packet is discarded after BBR has started sampling application data.

The optional `OnApplicationLimited` callback distinguishes an empty send
opportunity from cwnd, pacing, or send-queue blocking, including GSO sends.
Application-limited samples cannot lower the bandwidth maximum or falsely end
Startup. Restarting an idle connection refreshes the sampling epoch.

Lost MTU probes reduce bytes in flight and retire samples, but do not count as
congestion loss. Validated ECN-CE notifications use a conservative 0.7x response
once per flight; BBRv3's draft does not specify an ECN policy. QUIC PTO probes
are not treated as TCP RTOs.

The current transport API does not report a **spurious recovery episode** or a
**path migration reset** to external controllers. Accordingly, this adapter
cannot implement the draft's spurious-recovery undo, or reset its model at the
instant of path migration. The model adapts through subsequent feedback.

## Verification

From the dae repository root (which pins the local outbound and quic-go modules):

```sh
go test github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/congestion/...
go test github.com/daeuniverse/quic-go/internal/ackhandler github.com/daeuniverse/quic-go
```

Tests cover a paced finite-queue bottleneck with bandwidth increases/decreases
and random loss, state transitions, ProbeRTT, reordering, MTU probes, ECN, idle
restart, pacing deadlines, high-bandwidth arithmetic, and bidirectional real
QUIC transfers with and without UDP datagram loss. These are correctness and
integration checks, not a claim of improved performance on every Internet path.
