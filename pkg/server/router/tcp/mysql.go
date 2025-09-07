package tcp

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/rs/zerolog/log"
	tcpmuxer "github.com/traefik/traefik/v3/pkg/muxer/tcp"
	"github.com/traefik/traefik/v3/pkg/tcp"
	"io"
	"sync"
)

var (
	// MySQL Protocol Version 10 (MySQL 5.6+)
	MySQLProtocolVersion = byte(10)

	// MySQL capability flags for SSL support
	MySQLClientSSL = uint32(0x0800)

	// MySQL packet header size (4 bytes: 3 for length + 1 for sequence)
	MySQLPacketHeaderSize = 4
)

type MySQLHandshakePacket struct {
	ProtocolVersion byte
	ServerVersion   string
	ConnectionID    uint32
	AuthPluginData  []byte
	CapabilityFlags uint32
}

// hexdump печатает данные в стиле xxd
func hexdump(data []byte) {
	const bytesPerLine = 16
	length := len(data)
	if length > 0x200 {
		length = 0x200
	}

	for i := 0; i < length; i += bytesPerLine {
		// адрес (смещение)
		fmt.Printf("%08x: ", i)

		// байты
		end := i + bytesPerLine
		if end > length {
			end = length
		}
		for j := i; j < end; j++ {
			fmt.Printf("%02x ", data[j])
			// для читаемости делаем пробел после 8 байт
			if (j-i+1)%8 == 0 {
				fmt.Print(" ")
			}
		}

		// паддинг если строка короткая
		for j := end; j < i+bytesPerLine; j++ {
			fmt.Print("   ")
			if (j-i+1)%8 == 0 {
				fmt.Print(" ")
			}
		}

		// ascii справа
		fmt.Print(" ")
		for j := i; j < end; j++ {
			c := data[j]
			if c >= 32 && c <= 126 {
				fmt.Printf("%c", c)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println()
	}
}

func (r *Router) serveMySQL(conn tcp.WriteCloser) {
	br := bufio.NewReader(conn)

	// Send fake MySQL handshake packet to trigger client SSL negotiation
	handshakePacket := createMySQLHandshakePacketForceSSL()
	_, err := conn.Write(handshakePacket)
	if err != nil {
		log.Error().Err(err).Msg("Error sending MySQL handshake packet")
		conn.Close()
		return
	}

	// Read client response (MySQL SSL request + TLS ClientHello)
	clientResponse, err := readMySQLPacket(br)
	if err != nil {
		log.Error().Err(err).Msg("Error reading MySQL client response")
		conn.Close()
		return
	}

	// Check if client wants SSL
	if !isMySQLSSLRequest(clientResponse) {
		if r.IsMySQL() {
			log.Debug().Msg("MySQL protocol requires SSL for SNI extraction - closing connection")
			conn.Close()
			return
		}
		// Handle non-SSL MySQL connection
		r.handleNonSSLMySQL(conn, br)
		return
	}

	// Read TLS ClientHello with SNI (after MySQL packet)
	hello, err := clientHelloInfo(br)
	if err != nil {
		log.Error().Err(err).Msg("Error reading TLS ClientHello")
		conn.Close()
		return
	}

	if !hello.isTLS {
		log.Debug().Msg("Expected TLS connection but got non-TLS")
		conn.Close()
		return
	}

	// Check if SNI is present for MySQL protocol
	if hello.serverName == "" {
		log.Debug().Msg("MySQL protocol requires SNI for routing - closing connection")
		conn.Close()
		return
	}

	// Route based on SNI
	connData, err := tcpmuxer.NewConnData(hello.serverName, conn, hello.protos)
	if err != nil {
		log.Error().Err(err).Msg("Error while reading MySQL connection data")
		conn.Close()
		return
	}

	// Find handler for this SNI
	handlerTCPTLS, _ := r.muxerTCPTLS.Match(connData)
	if handlerTCPTLS == nil {
		log.Debug().Str("sni", hello.serverName).Msg("No route found for MySQL connection")
		conn.Close()
		return
	}

	// Create mysqlConn with client data for proper handshake replay
	mysqlConn := &mysqlConn{
		WriteCloser:     r.GetConn(conn, hello.peeked),
		clientSqlPacket: clientResponse,
		clientTLSHello:  []byte(hello.peeked),
	}

	handlerTCPTLS.ServeTCP(mysqlConn)
}

func (r *Router) handleNonSSLMySQL(conn tcp.WriteCloser, br *bufio.Reader) {
	// If this is a MySQL protocol entrypoint, we should not handle non-SSL connections
	if r.IsMySQL() {
		log.Debug().Msg("MySQL protocol requires SSL - closing non-SSL connection")
		conn.Close()
		return
	}

	// For non-SSL connections, we can't extract SNI, so route to default handler
	connData, err := tcpmuxer.NewConnData("", conn, nil)
	if err != nil {
		log.Error().Err(err).Msg("Error while reading non-SSL MySQL connection data")
		conn.Close()
		return
	}

	handler, _ := r.muxerTCP.Match(connData)
	if handler != nil {
		proxiedConn := r.GetConn(conn, getPeeked(br))
		mysqlConn := &mysqlConn{
			WriteCloser: proxiedConn,
		}
		handler.ServeTCP(mysqlConn)
	} else {
		conn.Close()
	}
}

func createMySQLHandshakePacketForceSSL() []byte {
	// Real MySQL handshake packet from server (captured from Wireshark)
	// This is the exact handshake packet that forces SSL negotiation
	// 4a 00 00 00 0a 38 2e 30 2e 34 33 00 0b 00 00 00 23 2f 19 20 79 3b 0d 10 00 ff ff ff 02 00 ff df 15 00 00 00 00 00 00 00 00 00 00 5f 53 19 3d 45 49 6a 7f 27 48 4a 7f 00 63 61 63 68 69 6e 67 5f 73 68 61 32 5f 70 61 73 73 77 6f 72 64 00

	realHandshakePacket := []byte{
		0x4a, 0x00, 0x00, 0x00, // Packet length: 74 bytes, sequence: 0
		0x0a, // Protocol version: 10
		// Server version: "8.0.43"
		0x38, 0x2e, 0x30, 0x2e, 0x34, 0x33, 0x00,
		//Thread ID: 1 (0x0b 0x00 0x00 0x00)
		0x10, 0x00, 0x00, 0x00,
		// Salt 9 bytes
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
		// Capability flags lower 2 bytes (0xffff = SSL + other capabilities)
		0xff, 0xff,
		// Server Langs
		0xFF,
		// Status flags
		0x02, 0x00,
		// Capability flags upper 2 bytes (0xffdf = SSL + other capabilities)
		0xff, 0xdf,
		// Auth plugin data length
		0x15,
		// Reserved (10 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Salt part 2 (13 bytes)
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
		// Auth plugin name: "caching_sha2_password"
		0x63, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x68, 0x61, 0x32, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
	}

	return realHandshakePacket
}

func readMySQLPacket(br *bufio.Reader) ([]byte, error) {
	// Read packet header (4 bytes)
	header := make([]byte, 4)
	_, err := io.ReadFull(br, header)
	if err != nil {
		return nil, err
	}

	// Extract packet length
	packetLength := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16

	// Read packet data
	packetData := make([]byte, packetLength)
	_, err = io.ReadFull(br, packetData)
	if err != nil {
		return nil, err
	}

	// Return header + data
	result := make([]byte, 4+packetLength)
	copy(result[:4], header)
	copy(result[4:], packetData)

	return result, nil
}

func isMySQLSSLRequest(packet []byte) bool {
	if len(packet) < 8 { // Header + minimum SSL request size
		return false
	}

	// Skip packet header (4 bytes)
	data := packet[4:]

	if len(data) < 4 {
		return false
	}

	// Extract capability flags from client packet
	capabilities := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24

	// Check if SSL capability is set
	return (capabilities & MySQLClientSSL) != 0
}

type mysqlConn struct {
	tcp.WriteCloser
	handshakeReceived bool
	flag              bool
	clientSqlPacket   []byte
	clientTLSHello    []byte
	errChanMu         sync.Mutex
	errChan           chan error
}

// принять данные от сервера
func (c *mysqlConn) Read(p []byte) (n int, err error) {
	if c.handshakeReceived {
		return c.WriteCloser.Read(p)
	}

	defer func() {
		c.handshakeReceived = true
		c.errChanMu.Lock()
		c.errChan = make(chan error)
		c.errChanMu.Unlock()
	}()

	copy(p, c.clientSqlPacket)

	return len(c.clientSqlPacket), nil

}

// отправить данные клиенту
func (c *mysqlConn) Write(p []byte) (n int, err error) {
	if c.flag {
		return c.WriteCloser.Write(p)
	}

	defer func() {
		c.flag = true
	}()
	br := bufio.NewReader(bytes.NewReader(p))

	clientResponse, err := readMySQLPacket(br)
	copy(p, clientResponse)

	return len(clientResponse), nil
}
