# MySQL SNI Routing with Traefik

This example demonstrates how to use Traefik's custom MySQL entrypoint to route MySQL connections based on Server Name Indication (SNI).

## Overview

The MySQL entrypoint enables routing MySQL connections to different backend databases based on the SNI (Server Name Indication) provided by the client during the TLS handshake.

## Features

- **SNI-based routing**: Route MySQL connections to different backends based on the requested hostname
- **TLS support**: Full SSL/TLS support for MySQL connections
- **Fallback routing**: Default routing for connections without SNI
- **Protocol detection**: Automatic detection of MySQL protocol handshake

## Configuration

### Traefik Configuration

```yaml
entrypoints:
  mysql:
    address: ":3306/mysql"
    mysql:
      sniRequired: true  # Optional: require SNI for all connections
```

### Docker Labels for MySQL Services

```yaml
labels:
  - traefik.enable=true
  - traefik.tcp.routers.mysql-db1.rule=HostSNI(`db1.example.com`)
  - traefik.tcp.routers.mysql-db1.entrypoints=mysql
  - traefik.tcp.routers.mysql-db1.service=mysql-db1-service
  - traefik.tcp.services.mysql-db1-service.loadbalancer.server.port=3306
  - traefik.tcp.routers.mysql-db1.tls=true
```

## How It Works

1. **Protocol Detection**: When a connection arrives on the MySQL entrypoint, Traefik detects the MySQL protocol by examining the initial handshake packet.

2. **SSL Negotiation**: If the client supports SSL, Traefik initiates the SSL negotiation process by sending a MySQL handshake packet with SSL capabilities.

3. **SNI Extraction**: During the TLS handshake, Traefik extracts the SNI (Server Name Indication) from the ClientHello message.

4. **Routing**: Based on the extracted SNI, Traefik routes the connection to the appropriate MySQL backend using the configured TCP routes.

5. **Connection Proxying**: The connection is then proxied to the target MySQL server while maintaining the protocol state.

## Usage

### Prerequisites

1. Generate SSL certificates for your MySQL domains:
   ```bash
   # Create certificates for db1.example.com and db2.example.com
   mkdir -p certs
   # Use your preferred method to generate certificates
   ```

2. Configure your MySQL servers to support SSL/TLS

### Running the Example

1. Start the services:
   ```bash
   docker-compose up -d
   ```

2. Test connections with different SNI values:
   ```bash
   # Connect to db1
   mysql -h db1.example.com -P 3306 -u testuser -p --ssl-mode=REQUIRED
   
   # Connect to db2  
   mysql -h db2.example.com -P 3306 -u testuser -p --ssl-mode=REQUIRED
   ```

### Client Configuration

For MySQL clients to work with SNI routing, they must:

1. **Support TLS/SSL**: The client must be configured to use SSL connections
2. **Provide SNI**: The client must send the correct hostname in the TLS handshake
3. **Trust certificates**: The client must trust the certificates used by the MySQL servers

Example MySQL client connection with SNI:
```bash
mysql -h db1.example.com -P 3306 -u testuser -p \
  --ssl-mode=REQUIRED \
  --ssl-ca=ca-cert.pem
```

## Architecture

```
Client (mysql -h db1.example.com) 
    ↓
Traefik MySQL EntryPoint (:3306/mysql)
    ↓
Protocol Detection (MySQL handshake)
    ↓
SSL Negotiation
    ↓
SNI Extraction (db1.example.com)
    ↓
Route Matching (HostSNI(`db1.example.com`))
    ↓
MySQL Backend Container (mysql-db1)
```

## Limitations

1. **Client SSL Support**: Clients must support SSL/TLS to enable SNI-based routing
2. **Protocol Overhead**: Additional handshake steps may introduce slight latency
3. **Certificate Management**: Each MySQL backend needs proper SSL certificate configuration

## Troubleshooting

### Connection Issues

1. **Check SSL Configuration**: Ensure MySQL servers are properly configured for SSL
2. **Verify Certificates**: Check that certificates match the SNI hostnames
3. **Client SSL Mode**: Ensure clients are using `--ssl-mode=REQUIRED` or similar
4. **Traefik Logs**: Check Traefik logs for protocol detection and routing information

### Debug Mode

Enable debug logging in Traefik to see detailed protocol handling:
```yaml
log:
  level: DEBUG
```

This will show MySQL protocol detection, SNI extraction, and routing decisions in the logs.

## Security Considerations

1. **Certificate Validation**: Always use proper SSL certificates in production
2. **Network Isolation**: Use Docker networks to isolate database traffic
3. **Access Control**: Implement proper MySQL user access controls
4. **Firewall Rules**: Restrict access to the MySQL entrypoint as needed
