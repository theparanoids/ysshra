package connection

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// GetConn returns a connection to the agent by connecting to a named pipe.
func GetConn(address string) (net.Conn, error) {
	return winio.DialPipe(address, nil)
}
