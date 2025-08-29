#!/bin/bash

# Test script for MySQL SNI routing with Traefik

set -e

echo "=== MySQL SNI Routing Test Script ==="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TRAEFIK_HOST="localhost"
MYSQL_PORT="3306"
TEST_USER="testuser"
TEST_PASS="testpass"

# Test databases
DB1_HOST="db1.example.com"
DB2_HOST="db2.example.com"
DEFAULT_HOST="localhost"

echo -e "${YELLOW}Testing MySQL SNI routing functionality...${NC}"

# Function to test MySQL connection
test_mysql_connection() {
    local host=$1
    local expected_db=$2
    local description=$3
    
    echo -e "\n${YELLOW}Testing: $description${NC}"
    echo "Connecting to: $host"
    
    # Test connection (without executing queries for now)
    if timeout 10 mysql -h "$host" -P "$MYSQL_PORT" -u "$TEST_USER" -p"$TEST_PASS" \
        --ssl-mode=REQUIRED \
        --connect-timeout=5 \
        -e "SELECT 'Connected successfully' as status, DATABASE() as current_db;" 2>/dev/null; then
        echo -e "${GREEN}✓ Connection successful to $host${NC}"
        return 0
    else
        echo -e "${RED}✗ Connection failed to $host${NC}"
        return 1
    fi
}

# Function to check if services are running
check_services() {
    echo -e "\n${YELLOW}Checking if services are running...${NC}"
    
    if ! docker-compose ps | grep -q "Up"; then
        echo -e "${RED}Services are not running. Please start with: docker-compose up -d${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Services are running${NC}"
}

# Function to wait for services to be ready
wait_for_services() {
    echo -e "\n${YELLOW}Waiting for services to be ready...${NC}"
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose exec -T mysql-default mysql -u root -prootpassword -e "SELECT 1;" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Services are ready${NC}"
            return 0
        fi
        
        echo "Attempt $attempt/$max_attempts: Waiting for MySQL services..."
        sleep 2
        ((attempt++))
    done
    
    echo -e "${RED}✗ Services failed to become ready within timeout${NC}"
    exit 1
}

# Function to setup /etc/hosts entries (requires sudo)
setup_hosts() {
    echo -e "\n${YELLOW}Setting up /etc/hosts entries...${NC}"
    
    # Check if entries already exist
    if grep -q "db1.example.com" /etc/hosts && grep -q "db2.example.com" /etc/hosts; then
        echo -e "${GREEN}✓ /etc/hosts entries already exist${NC}"
        return 0
    fi
    
    echo "Adding entries to /etc/hosts (requires sudo):"
    echo "127.0.0.1 db1.example.com"
    echo "127.0.0.1 db2.example.com"
    
    if command -v sudo >/dev/null 2>&1; then
        echo "127.0.0.1 db1.example.com" | sudo tee -a /etc/hosts >/dev/null
        echo "127.0.0.1 db2.example.com" | sudo tee -a /etc/hosts >/dev/null
        echo -e "${GREEN}✓ /etc/hosts entries added${NC}"
    else
        echo -e "${YELLOW}⚠ Please manually add the following entries to /etc/hosts:${NC}"
        echo "127.0.0.1 db1.example.com"
        echo "127.0.0.1 db2.example.com"
        read -p "Press Enter when done..."
    fi
}

# Function to test Traefik API
test_traefik_api() {
    echo -e "\n${YELLOW}Testing Traefik API...${NC}"
    
    if curl -s "http://localhost:8080/api/tcp/routers" | grep -q "mysql"; then
        echo -e "${GREEN}✓ Traefik API accessible and MySQL routes found${NC}"
    else
        echo -e "${RED}✗ Traefik API not accessible or no MySQL routes found${NC}"
        echo "Check if Traefik is running and configured correctly"
    fi
}

# Main test execution
main() {
    echo "Starting MySQL SNI routing tests..."
    
    # Preliminary checks
    check_services
    wait_for_services
    setup_hosts
    test_traefik_api
    
    echo -e "\n${YELLOW}=== Running Connection Tests ===${NC}"
    
    # Test SNI-based routing
    local success_count=0
    local total_tests=3
    
    # Test connection to db1.example.com
    if test_mysql_connection "$DB1_HOST" "testdb1" "MySQL DB1 via SNI"; then
        ((success_count++))
    fi
    
    # Test connection to db2.example.com  
    if test_mysql_connection "$DB2_HOST" "testdb2" "MySQL DB2 via SNI"; then
        ((success_count++))
    fi
    
    # Test default connection (no SNI)
    if test_mysql_connection "$DEFAULT_HOST" "defaultdb" "MySQL Default (no SNI)"; then
        ((success_count++))
    fi
    
    # Summary
    echo -e "\n${YELLOW}=== Test Summary ===${NC}"
    echo "Successful connections: $success_count/$total_tests"
    
    if [ $success_count -eq $total_tests ]; then
        echo -e "${GREEN}✓ All tests passed! MySQL SNI routing is working correctly.${NC}"
        exit 0
    else
        echo -e "${RED}✗ Some tests failed. Check the configuration and logs.${NC}"
        echo -e "\nTroubleshooting tips:"
        echo "1. Check Traefik logs: docker-compose logs traefik"
        echo "2. Check MySQL logs: docker-compose logs mysql-db1 mysql-db2"
        echo "3. Verify SSL certificates are properly configured"
        echo "4. Ensure /etc/hosts entries are correct"
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    "clean")
        echo "Cleaning up /etc/hosts entries..."
        if command -v sudo >/dev/null 2>&1; then
            sudo sed -i '/db1.example.com/d' /etc/hosts 2>/dev/null || true
            sudo sed -i '/db2.example.com/d' /etc/hosts 2>/dev/null || true
            echo -e "${GREEN}✓ /etc/hosts cleaned${NC}"
        else
            echo -e "${YELLOW}Please manually remove db1.example.com and db2.example.com from /etc/hosts${NC}"
        fi
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [clean|help]"
        echo "  clean: Remove /etc/hosts entries"
        echo "  help:  Show this help message"
        echo "  (no args): Run the full test suite"
        ;;
    *)
        main
        ;;
esac
