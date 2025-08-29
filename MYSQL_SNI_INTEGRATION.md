# MySQL SNI EntryPoint Integration for Traefik

## Overview

This implementation adds a custom MySQL entrypoint to Traefik that supports Server Name Indication (SNI) based routing for MySQL connections. The solution allows routing MySQL client connections to different backend MySQL servers based on the hostname specified in the TLS handshake.

## Architecture

### Key Components

1. **MySQL Protocol Handler** (`pkg/server/router/tcp/mysql.go`)
   - Detects MySQL protocol handshake packets
   - Manages SSL/TLS negotiation with MySQL clients
   - Extracts SNI from TLS ClientHello messages
   - Routes connections based on SNI to appropriate backends

2. **EntryPoint Configuration** (`pkg/config/static/entrypoints.go`)
   - Adds "mysql" as a valid protocol type
   - Introduces MySQLConfig for MySQL-specific settings
   - Supports `sniRequired` option for enforcing SNI

3. **Router Integration** (`pkg/server/router/tcp/router.go`)
   - Integrates MySQL detection into the main TCP routing logic
   - Handles MySQL connections before PostgreSQL and generic TCP

### Protocol Flow

```
1. Client connects to Traefik MySQL entrypoint (:3306/mysql)
2. Traefik detects MySQL protocol by examining handshake packet
3. Traefik sends MySQL handshake with SSL capabilities
4. Client responds with SSL request (if supported)
5. Traefik confirms SSL and waits for TLS ClientHello
6. SNI is extracted from ClientHello message
7. Connection is routed to appropriate backend based on SNI
8. TLS tunnel is established between client and backend
```

## Implementation Details

### MySQL Protocol Detection

The implementation detects MySQL connections by examining the initial packet structure:
- Packet header (4 bytes): length + sequence number
- Protocol version (1 byte): should be 10 for MySQL 5.6+
- Validates packet length and structure

### SNI Extraction Process

1. **Handshake Initiation**: Traefik sends a MySQL handshake packet with SSL capabilities
2. **SSL Negotiation**: Client responds with SSL request containing capability flags
3. **TLS Handshake**: Standard TLS handshake with SNI extraction
4. **Routing**: Connection routed based on extracted SNI using existing TCP routing logic

### Connection State Management

The `mysqlConn` wrapper maintains the MySQL protocol state:
- Tracks handshake completion
- Manages SSL negotiation state  
- Provides thread-safe read/write operations

## Configuration

### Static Configuration

```yaml
entryPoints:
  mysql:
    address: ":3306/mysql"
    mysql:
      sniRequired: true  # Optional: require SNI for routing
```

### Dynamic Configuration

```yaml
tcp:
  routers:
    mysql-db1:
      rule: "HostSNI(`db1.example.com`)"
      entryPoints: ["mysql"]
      service: mysql-db1-service
      tls: {}

  services:
    mysql-db1-service:
      loadBalancer:
        servers:
          - address: "mysql-server:3306"
```

## Usage Examples

### Docker Compose Setup

See `examples/mysql-sni/docker-compose.yml` for a complete Docker Compose setup with multiple MySQL backends.

### Client Connections

```bash
# Connect with SNI to specific database
mysql -h db1.example.com -P 3306 -u testuser -p --ssl-mode=REQUIRED

# Connect to different database via SNI
mysql -h db2.example.com -P 3306 -u testuser -p --ssl-mode=REQUIRED
```

## Testing

### Automated Tests

Run the test suite:
```bash
cd examples/mysql-sni
./test-mysql-sni.sh
```

### Manual Testing

1. **Start Services**:
   ```bash
   docker-compose up -d
   ```

2. **Check Traefik Dashboard**:
   - Open http://localhost:8080
   - Verify MySQL routers are loaded

3. **Test Connections**:
   ```bash
   # Test each configured database
   mysql -h db1.example.com -P 3306 -u testuser -p --ssl-mode=REQUIRED
   mysql -h db2.example.com -P 3306 -u testuser -p --ssl-mode=REQUIRED
   ```

## Limitations and Considerations

### Current Limitations

1. **SSL Requirement**: SNI-based routing requires SSL/TLS enabled MySQL connections
2. **Client Support**: MySQL clients must support SNI (most modern clients do)
3. **Protocol Overhead**: Additional handshake steps introduce minimal latency

### Security Considerations

1. **Certificate Management**: Each MySQL backend needs proper SSL certificates
2. **Network Isolation**: Use Docker networks or VPNs to isolate database traffic
3. **Access Control**: Implement MySQL user authentication and authorization
4. **Monitoring**: Enable Traefik access logs and metrics for auditing

### Performance Considerations

1. **Connection Pooling**: Configure appropriate MySQL connection limits
2. **Keep-Alive**: Tune TCP keep-alive settings for long-lived connections
3. **Buffer Sizes**: Adjust buffer sizes for high-throughput scenarios

## Troubleshooting

### Common Issues

1. **Connection Refused**:
   - Check if Traefik is listening on the MySQL port
   - Verify entrypoint configuration

2. **SSL Handshake Failures**:
   - Ensure MySQL servers have valid SSL certificates
   - Check client SSL configuration

3. **Routing Issues**:
   - Verify SNI hostname matches router rules
   - Check /etc/hosts or DNS configuration
   - Review Traefik debug logs

### Debug Information

Enable debug logging to troubleshoot:
```yaml
log:
  level: DEBUG
```

Key log messages to look for:
- "MySQL protocol detected"
- "SNI extracted: [hostname]"
- "Routing to backend: [service]"

## Future Enhancements

### Potential Improvements

1. **Non-SSL Support**: Add routing for non-SSL MySQL connections using connection metadata
2. **Load Balancing**: Enhanced load balancing strategies for MySQL clusters
3. **Health Checks**: MySQL-specific health check implementations
4. **Metrics**: MySQL connection metrics and monitoring
5. **Authentication**: Integration with MySQL authentication plugins

### Compatibility

- **MySQL Versions**: Tested with MySQL 5.7+ and 8.0+
- **Client Libraries**: Compatible with standard MySQL clients and libraries
- **Traefik Versions**: Designed for Traefik v3.0+

## Contributing

When contributing to this MySQL SNI implementation:

1. **Testing**: Ensure all tests pass and add new tests for new functionality
2. **Documentation**: Update documentation for any configuration changes  
3. **Compatibility**: Maintain backward compatibility with existing TCP routing
4. **Performance**: Consider performance impact of protocol detection logic

## References

- [MySQL Protocol Documentation](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol.html)
- [TLS SNI Extension RFC](https://tools.ietf.org/html/rfc6066#section-3)
- [Traefik TCP Routing](https://doc.traefik.io/traefik/routing/routers/#tcp-routers)

## Files Modified

### Core Implementation
- `pkg/server/router/tcp/mysql.go` - MySQL protocol handler
- `pkg/server/router/tcp/router.go` - Router integration
- `pkg/config/static/entrypoints.go` - Configuration support
- `pkg/server/server_entrypoint_tcp.go` - EntryPoint support

### Tests and Examples
- `pkg/server/router/tcp/mysql_test.go` - Unit tests
- `examples/mysql-sni/` - Complete example setup
- `examples/mysql-sni/test-mysql-sni.sh` - Test script

This implementation provides a robust foundation for MySQL SNI routing in Traefik while maintaining compatibility with existing TCP routing functionality.
