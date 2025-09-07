package tcp

import (
	"bufio"
	"bytes"
	"github.com/rs/zerolog/log"
	tcpmuxer "github.com/traefik/traefik/v3/pkg/muxer/tcp"
	"github.com/traefik/traefik/v3/pkg/tcp"
	"io"
)

var (
	// MySQL Protocol Version 10 (MySQL 5.6+)
	MySQLProtocolVersion = byte(10)

	// MySQL capability flags for SSL support
	MySQLClientSSL = uint32(0x0800)
)

type MySQLHandshakePacket struct {
	ProtocolVersion byte
	ServerVersion   string
	ConnectionID    uint32
	AuthPluginData  []byte
	CapabilityFlags uint32
}

// serveMySQL handles MySQL protocol connections with TLS passthrough.
// It sends a fake handshake to the client, extracts SNI from the client's TLS ClientHello,
// and creates a mysqlConn to handle the handshake replay to the backend.
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
		WriteCloser:      r.GetConn(conn, hello.peeked),
		clientSSLRequest: clientResponse,
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

// createMySQLHandshakePacketForceSSL creates a fake MySQL handshake packet
// that forces the client to initiate SSL negotiation.
// This packet is based on a real MySQL 8.0.43 handshake captured from Wireshark.
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

// readMySQLPacket reads a complete MySQL packet (header + payload) from the connection.
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

// isMySQLSSLRequest checks if a MySQL packet contains an SSL request.
// It examines the capability flags in the client packet to determine if SSL is requested.
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

// mysqlConn wraps a TCP connection to handle MySQL TLS handshake passthrough.
// It stores the client's SSL request packet and replays it to the backend server.
type mysqlConn struct {
	tcp.WriteCloser

	// Connection state
	handshakeCompleted bool // whether the initial handshake phase is completed
	proxyMode          bool // whether we're in normal proxy mode (after handshake)

	// Client data to replay to backend
	clientSSLRequest []byte // the original SSL request packet from client
}

// Read reads data from the backend server.
// On first call, it replays the client's SSL request to the backend.
// Subsequent calls proxy data normally from backend to client.
func (c *mysqlConn) Read(p []byte) (n int, err error) {
	// If handshake is completed, proxy data normally
	if c.handshakeCompleted {
		return c.WriteCloser.Read(p)
	}

	// First call: replay client's SSL request to backend
	defer func() {
		c.handshakeCompleted = true
	}()

	// Send the client's SSL request packet to the backend
	copy(p, c.clientSSLRequest)
	return len(c.clientSSLRequest), nil
}

// Write writes data to the client.
// On first call, it processes the backend's MySQL handshake response.
// Subsequent calls proxy data normally from backend to client.
func (c *mysqlConn) Write(p []byte) (n int, err error) {
	// If we're in proxy mode, forward all data to client
	if c.proxyMode {
		return c.WriteCloser.Write(p)
	}

	// First call: process backend's MySQL handshake response
	defer func() {
		c.proxyMode = true
	}()

	// Parse the MySQL packet from backend response
	br := bufio.NewReader(bytes.NewReader(p))
	backendResponse, err := readMySQLPacket(br)
	if err != nil {
		return 0, err
	}

	// Forward the parsed MySQL response to client
	copy(p, backendResponse)
	return len(backendResponse), nil
}
