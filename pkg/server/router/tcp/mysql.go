package tcp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/rs/zerolog/log"
	tcpmuxer "github.com/traefik/traefik/v3/pkg/muxer/tcp"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

// MySQL Protocol Constants
var (
	// MySQL Protocol Version 10 (MySQL 5.6+)
	MySQLProtocolVersion = byte(10)

	// MySQL capability flags for SSL support
	MySQLClientSSL = uint32(0x0800)

	// MySQL packet header size (4 bytes: 3 for length + 1 for sequence)
	MySQLPacketHeaderSize = 4
)

// MySQLHandshakePacket represents the initial handshake packet from MySQL server
type MySQLHandshakePacket struct {
	ProtocolVersion byte
	ServerVersion   string
	ConnectionID    uint32
	AuthPluginData  []byte
	CapabilityFlags uint32
}

// isMySQLHandshake determines whether the buffer contains a MySQL handshake packet.
func isMySQLHandshake(br *bufio.Reader) (bool, error) {
	log.Info().Msg("isMySQLHandshake")
	peeked, err := br.Peek(5)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, err
	}

	// Первые 3 байта — длина пакета (little endian)
	length := int(peeked[0]) | int(peeked[1])<<8 | int(peeked[2])<<16
	seq := peeked[3]
	protocol := peeked[4]

	// Проверяем что sequence = 0 и protocol version = 0x0a
	if seq == 0x00 && protocol == 0x0a && length > 0 {
		log.Info().Msg("isMySQLHandshake: MySql Detected!!!!")
		return true, nil
	}

	return false, nil
}

// serveMySQL serves a connection with a MySQL client that may negotiate SSL/TLS.
// It handles MySQL protocol detection and SNI extraction for routing.
func (r *Router) serveMySQL(conn tcp.WriteCloser) {
	log.Info().Msg("\n\n\nserveMySQL\n\n\n")
	br := bufio.NewReader(conn)

	// For MySQL, we need to send the handshake packet first to initiate SSL negotiation
	// This is different from PostgreSQL where client sends STARTTLS request first

	// Create a fake MySQL handshake packet to trigger client SSL negotiation
	handshakePacket := createMySQLHandshakePacket()

	_, err := conn.Write(handshakePacket)
	if err != nil {
		log.Error().Err(err).Msg("Error sending MySQL handshake packet")
		conn.Close()
		return
	}

	// Read client response - should be SSL request if TLS is supported
	clientResponse, err := readMySQLPacket(br)
	if err != nil {
		log.Error().Err(err).Msg("Error reading MySQL client response")
		conn.Close()
		return
	}

	// Check if client wants SSL
	if !isMySQLSSLRequest(clientResponse) {
		// Handle non-SSL MySQL connection
		r.handleNonSSLMySQL(conn, br)
		return
	}

	// Send SSL OK response
	sslOKPacket := createMySQLSSLOKPacket()
	_, err = conn.Write(sslOKPacket)
	if err != nil {
		log.Error().Err(err).Msg("Error sending MySQL SSL OK packet")
		conn.Close()
		return
	}

	// Now expect TLS ClientHello with SNI
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

	log.Debug().Msg("\n\n\nSNI DETECTED! \n\n\n")
	log.Debug().Str("sni", hello.serverName)
	// Route based on SNI
	connData, err := tcpmuxer.NewConnData(hello.serverName, conn, hello.protos)
	if err != nil {
		log.Error().Err(err).Msg("Error while reading MySQL connection data")
		conn.Close()
		return
	}

	// Look for MySQL-specific routes first, then fallback to TCP TLS routes
	handlerTCPTLS, _ := r.muxerTCPTLS.Match(connData)
	if handlerTCPTLS == nil {
		log.Debug().Str("sni", hello.serverName).Msg("No route found for MySQL connection")
		conn.Close()
		return
	}

	// Create MySQL-aware connection wrapper
	proxiedConn := r.GetConn(conn, hello.peeked)
	mysqlConn := &mysqlConn{
		WriteCloser:   proxiedConn,
		handshakeSent: true,
		sslNegotiated: true,
	}

	handlerTCPTLS.ServeTCP(mysqlConn)
}

// handleNonSSLMySQL handles non-SSL MySQL connections
func (r *Router) handleNonSSLMySQL(conn tcp.WriteCloser, br *bufio.Reader) {
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
			WriteCloser:   proxiedConn,
			handshakeSent: true,
			sslNegotiated: false,
		}
		handler.ServeTCP(mysqlConn)
	} else {
		conn.Close()
	}
}

// createMySQLHandshakePacket creates a MySQL server handshake packet
func createMySQLHandshakePacket() []byte {
	// Simplified MySQL handshake packet for SSL negotiation
	// This is a minimal implementation to trigger SSL negotiation

	serverVersion := "8.0.0-traefik\x00" // Null-terminated server version
	authPluginData := make([]byte, 8)    // First part of auth data

	// Capability flags (including SSL support)
	capabilities := MySQLClientSSL | 0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0200

	var packet bytes.Buffer

	// Protocol version
	packet.WriteByte(MySQLProtocolVersion)

	// Server version
	packet.WriteString(serverVersion)

	// Connection ID (4 bytes)
	packet.Write([]byte{0x01, 0x00, 0x00, 0x00})

	// First part of auth plugin data (8 bytes)
	packet.Write(authPluginData)

	// Filler (1 byte)
	packet.WriteByte(0x00)

	// Capability flags lower 2 bytes
	packet.WriteByte(byte(capabilities & 0xFF))
	packet.WriteByte(byte((capabilities >> 8) & 0xFF))

	// Character set (1 byte)
	packet.WriteByte(0x21) // utf8_general_ci

	// Status flags (2 bytes)
	packet.Write([]byte{0x00, 0x00})

	// Capability flags upper 2 bytes
	packet.WriteByte(byte((capabilities >> 16) & 0xFF))
	packet.WriteByte(byte((capabilities >> 24) & 0xFF))

	// Auth plugin data length
	packet.WriteByte(0x15) // 21 bytes total auth data length

	// Reserved (10 bytes)
	packet.Write(make([]byte, 10))

	// Second part of auth plugin data (12 bytes)
	packet.Write(make([]byte, 12))

	// Null terminator
	packet.WriteByte(0x00)

	// Auth plugin name
	packet.WriteString("mysql_native_password\x00")

	// Create packet with header
	packetData := packet.Bytes()
	packetLength := len(packetData)

	result := make([]byte, 4+packetLength)

	// Packet length (3 bytes, little endian)
	result[0] = byte(packetLength & 0xFF)
	result[1] = byte((packetLength >> 8) & 0xFF)
	result[2] = byte((packetLength >> 16) & 0xFF)

	// Sequence number
	result[3] = 0x00

	// Packet data
	copy(result[4:], packetData)

	return result
}

// readMySQLPacket reads a MySQL packet from the connection
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

// isMySQLSSLRequest checks if the client packet is an SSL request
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

// createMySQLSSLOKPacket creates a MySQL SSL OK response
func createMySQLSSLOKPacket() []byte {
	// Simple OK packet to confirm SSL negotiation
	// Packet length: 1 byte, Sequence: 1, OK indicator: 0x00
	return []byte{0x01, 0x00, 0x00, 0x01, 0x00}
}

// mysqlConn is a tcp.WriteCloser wrapper for MySQL connections
// It handles the MySQL protocol handshake state
type mysqlConn struct {
	tcp.WriteCloser

	handshakeSent bool
	sslNegotiated bool

	// For handling the protocol state
	mu sync.Mutex
}

// Read implements the MySQL protocol state machine for reads
func (c *mysqlConn) Read(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.WriteCloser.Read(p)
}

// Write implements the MySQL protocol state machine for writes
func (c *mysqlConn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.WriteCloser.Write(p)
}
