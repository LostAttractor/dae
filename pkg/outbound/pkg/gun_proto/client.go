// Package gun_proto implements the client side of the Gun byte-stream RPC.
package gun_proto

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
)

// Hunk is the wire message: protobuf field 1 contains the stream bytes.
type Hunk struct{ Data []byte }

type Tunnel interface {
	Context() context.Context
	Send(*Hunk) error
	Recv() (*Hunk, error)
	CloseSend() error
}

type tunnel struct{ grpc.ClientStream }

func Open(ctx context.Context, cc grpc.ClientConnInterface, service string) (Tunnel, error) {
	if service == "" {
		service = "GunService"
	}
	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/"+service+"/Tun", grpc.ForceCodec(codec{}))
	if err != nil {
		return nil, err
	}
	return &tunnel{stream}, nil
}
func (t *tunnel) Send(h *Hunk) error { return t.SendMsg(h) }
func (t *tunnel) Recv() (*Hunk, error) {
	h := new(Hunk)
	if err := t.RecvMsg(h); err != nil {
		return nil, err
	}
	return h, nil
}

type codec struct{}

func (codec) Name() string { return "proto" }
func (codec) Marshal(value any) ([]byte, error) {
	h, ok := value.(*Hunk)
	if !ok {
		return nil, fmt.Errorf("gun: unsupported message %T", value)
	}
	if len(h.Data) == 0 {
		return nil, nil
	}
	wire := make([]byte, 0, 1+protowire.SizeBytes(len(h.Data)))
	wire = protowire.AppendTag(wire, 1, protowire.BytesType)
	return protowire.AppendBytes(wire, h.Data), nil
}
func (codec) Unmarshal(wire []byte, value any) error {
	h, ok := value.(*Hunk)
	if !ok {
		return fmt.Errorf("gun: unsupported message %T", value)
	}
	h.Data = nil
	for len(wire) != 0 {
		field, kind, n := protowire.ConsumeTag(wire)
		if n < 0 {
			return protowire.ParseError(n)
		}
		wire = wire[n:]
		if field == 1 {
			if kind != protowire.BytesType {
				return fmt.Errorf("gun: data field has wire type %d", kind)
			}
			data, size := protowire.ConsumeBytes(wire)
			if size < 0 {
				return protowire.ParseError(size)
			}
			// gRPC owns wire and may release it as soon as Unmarshal returns.
			h.Data = append(h.Data[:0], data...)
			wire = wire[size:]
		} else {
			size := protowire.ConsumeFieldValue(field, kind, wire)
			if size < 0 {
				return protowire.ParseError(size)
			}
			wire = wire[size:]
		}
	}
	return nil
}
