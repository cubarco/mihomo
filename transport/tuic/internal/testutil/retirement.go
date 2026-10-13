package testutil

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/tuic/types"
	"github.com/metacubex/quic-go"
	"github.com/stretchr/testify/require"
)

func CheckClientRetirement(t *testing.T, create func(types.DialFunc) (types.Client, func())) {
	t.Helper()
	for _, udp := range []bool{false, true} {
		t.Run(fmt.Sprintf("udp-%t", udp), func(t *testing.T) {
			t.Parallel()
			client, retire := create(func(context.Context) (*quic.Conn, error) {
				return ConnectedQUIC(t, 10), nil
			})
			t.Cleanup(retire)
			metadata := &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
			open := func() io.Closer {
				t.Helper()
				if udp {
					pc, err := client.ListenPacket(context.Background(), metadata)
					require.NoError(t, err)
					return pc
				}
				conn, err := client.DialContext(context.Background(), metadata)
				require.NoError(t, err)
				return conn
			}
			old := open()
			if !udp {
				require.NoError(t, old.Close())
			}
			retire()
			current := open()
			defer current.Close()
			require.EqualValues(t, 1, client.OpenStreams())
			if udp {
				_ = old.Close()
				pc := current.(net.PacketConn)
				require.NoError(t, pc.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
				_, _, err := pc.ReadFrom(make([]byte, 64))
				require.ErrorIs(t, err, os.ErrDeadlineExceeded, "a retired UDP stream closed the replacement's input")
			}
			time.Sleep(C.DefaultTCPTimeout + 100*time.Millisecond)
			require.EqualValues(t, 1, client.OpenStreams(), "the old grace callback changed the replacement's stream count")
		})
	}
}

func CheckClientGraceClose(t *testing.T, create func(types.DialFunc) (types.Client, func())) {
	t.Helper()
	for _, udp := range []bool{false, true} {
		t.Run(fmt.Sprintf("udp-%t", udp), func(t *testing.T) {
			t.Parallel()
			transport := ConnectedQUIC(t, 10)
			client, retire := create(func(context.Context) (*quic.Conn, error) { return transport, nil })
			t.Cleanup(retire)
			metadata := &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
			var stream io.Closer
			var err error
			if udp {
				stream, err = client.ListenPacket(context.Background(), metadata)
			} else {
				stream, err = client.DialContext(context.Background(), metadata)
			}
			require.NoError(t, err)
			client.Close()
			require.NoError(t, transport.Context().Err(), "graceful close interrupted a live stream")
			require.NoError(t, stream.Close())
			require.NoError(t, stream.Close())
			require.EqualValues(t, 1, client.OpenStreams(), "closing the stream skipped its grace period")
			select {
			case <-transport.Context().Done():
			case <-time.After(C.DefaultTCPTimeout + time.Second):
				t.Fatal("the transport outlived its final stream's grace period")
			}
			require.Zero(t, client.OpenStreams())
		})
	}
}
