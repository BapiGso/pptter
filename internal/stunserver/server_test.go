package stunserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func TestServerAnswersBindingRequest(test *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, err := Start(ctx, 0)
	if err != nil {
		test.Fatalf("start stun server: %v", err)
	}
	defer server.Close()

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		test.Fatalf("listen client udp: %v", err)
	}
	defer clientConn.Close()

	if err := clientConn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		test.Fatalf("set client deadline: %v", err)
	}

	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	serverAddress := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: server.Port()}
	if _, err := clientConn.WriteTo(request.Raw, serverAddress); err != nil {
		test.Fatalf("write binding request: %v", err)
	}

	buffer := make([]byte, maxDatagramBytes)
	bytesRead, _, err := clientConn.ReadFrom(buffer)
	if err != nil {
		test.Fatalf("read binding response: %v", err)
	}

	response := &stun.Message{Raw: buffer[:bytesRead]}
	if err := response.Decode(); err != nil {
		test.Fatalf("decode binding response: %v", err)
	}
	if response.Type != stun.BindingSuccess {
		test.Fatalf("response type = %s, want %s", response.Type, stun.BindingSuccess)
	}
	if response.TransactionID != request.TransactionID {
		test.Fatalf("response transaction id changed")
	}

	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(response); err != nil {
		test.Fatalf("read xor-mapped-address: %v", err)
	}

	localAddress := clientConn.LocalAddr().(*net.UDPAddr)
	if !mapped.IP.Equal(net.ParseIP("127.0.0.1")) {
		test.Fatalf("mapped ip = %s, want 127.0.0.1", mapped.IP)
	}
	if mapped.Port != localAddress.Port {
		test.Fatalf("mapped port = %d, want %d", mapped.Port, localAddress.Port)
	}
}

func TestServerStopsWhenContextIsCanceled(test *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	server, err := Start(ctx, 0)
	if err != nil {
		test.Fatalf("start stun server: %v", err)
	}

	cancel()

	select {
	case <-server.done:
	case <-time.After(time.Second):
		test.Fatal("stun server did not stop after context cancellation")
	}

	if server.Running() {
		test.Fatal("server reports running after context cancellation")
	}
}
