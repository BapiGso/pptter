package stunserver

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"

	"github.com/pion/stun/v3"
)

const (
	DefaultPort      = 3478
	maxDatagramBytes = 1500
)

type Server struct {
	conn      net.PacketConn
	done      chan struct{}
	closeOnce sync.Once
	port      int
}

func Start(ctx context.Context, port int) (*Server, error) {
	if port < 0 || port > 65535 {
		return nil, errors.New("stun port must be between 0 and 65535")
	}

	conn, err := net.ListenPacket("udp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}

	server := &Server{
		conn: conn,
		done: make(chan struct{}),
		port: boundPort(conn.LocalAddr()),
	}

	go server.serve()

	if ctx != nil {
		if done := ctx.Done(); done != nil {
			go func() {
				<-done
				_ = server.Close()
			}()
		}
	}

	return server, nil
}

func (server *Server) Port() int {
	if server == nil {
		return 0
	}
	return server.port
}

func (server *Server) Running() bool {
	if server == nil {
		return false
	}

	select {
	case <-server.done:
		return false
	default:
		return true
	}
}

func (server *Server) Close() error {
	if server == nil {
		return nil
	}

	var closeErr error
	server.closeOnce.Do(func() {
		closeErr = server.conn.Close()
		<-server.done
	})
	return closeErr
}

func (server *Server) serve() {
	defer close(server.done)

	buffer := make([]byte, maxDatagramBytes)
	for {
		bytesRead, address, err := server.conn.ReadFrom(buffer)
		if err != nil {
			return
		}

		server.handlePacket(buffer[:bytesRead], address)
	}
}

func (server *Server) handlePacket(packet []byte, address net.Addr) {
	if !stun.IsMessage(packet) {
		return
	}

	udpAddress, ok := address.(*net.UDPAddr)
	if !ok {
		return
	}

	request := &stun.Message{Raw: packet}
	if err := request.Decode(); err != nil {
		return
	}
	if request.Type != stun.BindingRequest {
		return
	}

	response, err := stun.Build(
		stun.BindingSuccess,
		stun.NewTransactionIDSetter(request.TransactionID),
		stun.XORMappedAddress{IP: udpAddress.IP, Port: udpAddress.Port},
	)
	if err != nil {
		return
	}

	_, _ = server.conn.WriteTo(response.Raw, address)
}

func boundPort(address net.Addr) int {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok {
		return 0
	}
	return udpAddress.Port
}
