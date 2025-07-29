#!/usr/bin/env bash
# mullvad-socks5-proxy.sh

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Check if server parameter is provided
if [ -n "$2" ]; then
    SERVER="$2"
    CONFIG_FILE="/etc/mullvad-socks5-proxy/${SERVER}.conf"
else
    SERVER="default"
    CONFIG_FILE="/etc/mullvad-socks5-proxy/default.conf"
fi

INTERNAL_SOCKS5_PORT="1080"  # Mullvad's internal SOCKS5 port (fixed)

# Function to parse WireGuard config and extract values
parse_wg_config() {
    local config_file="$1"

    if [ ! -f "$config_file" ]; then
        echo "Error: Config file $config_file not found!"
        return 1
    fi

    # Extract PrivateKey
    PRIVATE_KEY=$(grep "^PrivateKey" "$config_file" | sed 's/^PrivateKey[[:space:]]*=[[:space:]]*//')

    # Extract Address (IPv4 and IPv6)
    ADDRESS_LINE=$(grep "^Address" "$config_file" | sed 's/^Address[[:space:]]*=[[:space:]]*//')
    IPV4_ADDR=$(echo "$ADDRESS_LINE" | cut -d',' -f1)
    IPV6_ADDR=$(echo "$ADDRESS_LINE" | cut -d',' -f2)

    # Extract PublicKey
    PUBLIC_KEY=$(grep "^PublicKey" "$config_file" | sed 's/^PublicKey[[:space:]]*=[[:space:]]*//')

    # Extract Endpoint
    ENDPOINT=$(grep "^Endpoint" "$config_file" | sed 's/^Endpoint[[:space:]]*=[[:space:]]*//')

    # Extract AllowedIPs (but override for VPN proxy functionality)
    # Original: ALLOWED_IPS=$(grep "^AllowedIPs" "$config_file" | sed 's/^AllowedIPs[[:space:]]*=[[:space:]]*//')
    # For VPN proxy, we need to route all traffic through WireGuard
    ALLOWED_IPS="0.0.0.0/0,::0/0"

    # Extract DNS (if present and not commented)
    DNS_SERVER=$(grep "^DNS" "$config_file" | sed 's/^DNS[[:space:]]*=[[:space:]]*//')
    if [ -z "$DNS_SERVER" ]; then
        DNS_SERVER="10.64.0.1"  # Default Mullvad DNS
    fi

    # Extract custom SOCKS5 port from [Custom] section
    EXTERNAL_SOCKS5_PORT=$(grep "^SOCKS5Port" "$config_file" | sed 's/^SOCKS5Port[[:space:]]*=[[:space:]]*//')
    if [ -z "$EXTERNAL_SOCKS5_PORT" ]; then
        EXTERNAL_SOCKS5_PORT="1080"  # Default external port
    fi
}

# Function to set port-based naming after parsing config
set_port_based_names() {
    NAMESPACE="mvd_mullvad_$EXTERNAL_SOCKS5_PORT"
    INTERFACE="wg$EXTERNAL_SOCKS5_PORT"
    VETH_HOST="vh$EXTERNAL_SOCKS5_PORT"
    VETH_NS="vn$EXTERNAL_SOCKS5_PORT"
}

# Function to clean up any existing resources
cleanup_existing() {
    echo "Cleaning up any existing resources for $SERVER..."

    # Parse config to get port-based names if not already set
    if [ -z "$EXTERNAL_SOCKS5_PORT" ]; then
        parse_wg_config "$CONFIG_FILE" 2>/dev/null
        set_port_based_names
    fi

    # Kill main script process if running
    [ -f "/tmp/mullvad-main-$SERVER.pid" ] && kill $(cat "/tmp/mullvad-main-$SERVER.pid") 2>/dev/null && rm "/tmp/mullvad-main-$SERVER.pid"

    # Kill existing processes
    [ -f "/tmp/mullvad-socat-$SERVER.pid" ] && kill $(cat "/tmp/mullvad-socat-$SERVER.pid") 2>/dev/null && rm "/tmp/mullvad-socat-$SERVER.pid"
    [ -f "/tmp/mullvad-socks5-$SERVER.pid" ] && kill $(cat "/tmp/mullvad-socks5-$SERVER.pid") 2>/dev/null && rm "/tmp/mullvad-socks5-$SERVER.pid"

    # Remove veth interfaces (if names are set)
    if [ -n "$VETH_HOST" ]; then
        ip link delete "$VETH_HOST" 2>/dev/null
    fi

    # Remove namespace (this also removes interfaces inside it)
    if [ -n "$NAMESPACE" ]; then
        ip netns delete "$NAMESPACE" 2>/dev/null
        rm -rf "/etc/netns/$NAMESPACE" 2>/dev/null
    fi

    # Clean up temporary files
    rm -f /tmp/simple-socks5.py "/tmp/wg-$SERVER.conf"

    # Wait a moment for cleanup to complete
    sleep 1
}

setup_namespace() {
    echo "Setting up Mullvad proxy for server: $SERVER"

    # Parse the WireGuard configuration first to get the port
    parse_wg_config "$CONFIG_FILE"
    if [ $? -ne 0 ]; then
        return 1
    fi

    # Set port-based naming after parsing config
    set_port_based_names

    # Clean up any existing resources first
    cleanup_existing

    echo "Creating network namespace: $NAMESPACE"
    ip netns add "$NAMESPACE"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create network namespace"
        return 1
    fi

    # Check namespace file permissions
    echo "Checking namespace file permissions..."
    ls -la "/var/run/netns/$NAMESPACE" 2>/dev/null

    # Test namespace immediately after creation
    echo "Testing namespace access..."
    ip netns exec "$NAMESPACE" echo "Namespace test successful" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Cannot access newly created namespace"
        cleanup_existing
        return 1
    fi

    echo "Setting up WireGuard interface: $INTERFACE"
    ip link add "$INTERFACE" type wireguard
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create WireGuard interface"
        cleanup_existing
        return 1
    fi

    # Test namespace before moving interface
    echo "Testing namespace before moving interface..."
    ip netns exec "$NAMESPACE" echo "Pre-move test successful" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Namespace became inaccessible before moving interface"
        cleanup_existing
        return 1
    fi

    echo "Moving WireGuard interface to namespace..."
    ip link set "$INTERFACE" netns "$NAMESPACE"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to move interface to namespace"
        cleanup_existing
        return 1
    fi

    # Test namespace after moving interface
    echo "Testing namespace after moving interface..."
    ip netns exec "$NAMESPACE" echo "Post-move test successful" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Namespace became inaccessible after moving interface"
        cleanup_existing
        return 1
    fi

    # Create temporary WireGuard config from parsed values
    echo "Creating WireGuard configuration..."
    cat > "/tmp/wg-$SERVER.conf" << EOF
[Interface]
PrivateKey = $PRIVATE_KEY

[Peer]
PublicKey = $PUBLIC_KEY
AllowedIPs = $ALLOWED_IPS
Endpoint = $ENDPOINT
EOF

    echo "Configuring WireGuard interface..."
    ip netns exec "$NAMESPACE" wg setconf "$INTERFACE" "/tmp/wg-$SERVER.conf"

    if [ $? -ne 0 ]; then
        echo "Error configuring WireGuard interface"
        cleanup_existing
        return 1
    fi

    echo "Setting up IP addresses..."
    ip netns exec "$NAMESPACE" ip addr add "$IPV4_ADDR" dev "$INTERFACE"
    if [ -n "$IPV6_ADDR" ]; then
        ip netns exec "$NAMESPACE" ip addr add "$IPV6_ADDR" dev "$INTERFACE"
    fi
    ip netns exec "$NAMESPACE" ip link set "$INTERFACE" up

    echo "Setting up routing..."
    ip netns exec "$NAMESPACE" ip route add default dev "$INTERFACE"

    # Set up DNS in the namespace
    echo "Setting up DNS..."
    mkdir -p "/etc/netns/$NAMESPACE"
    echo "nameserver $DNS_SERVER" | tee "/etc/netns/$NAMESPACE/resolv.conf" > /dev/null

    echo "Creating SOCKS5 proxy script..."
    cat > /tmp/simple-socks5.py << 'EOF'
#!/usr/bin/env python3
import socket
import threading
import struct
import sys

def handle_client(client_socket):
    try:
        # SOCKS5 authentication
        data = client_socket.recv(262)
        if len(data) < 3 or data[0] != 0x05:
            client_socket.close()
            return

        # No authentication required
        client_socket.send(b'\x05\x00')

        # SOCKS5 request
        data = client_socket.recv(4)
        if len(data) < 4 or data[0] != 0x05 or data[1] != 0x01:
            client_socket.close()
            return

        # Parse address
        if data[3] == 0x01:  # IPv4
            addr_data = client_socket.recv(6)
            addr = socket.inet_ntoa(addr_data[:4])
            port = struct.unpack('>H', addr_data[4:6])[0]
        elif data[3] == 0x03:  # Domain name
            domain_len = client_socket.recv(1)[0]
            domain_data = client_socket.recv(domain_len + 2)
            addr = domain_data[:-2].decode('utf-8')
            port = struct.unpack('>H', domain_data[-2:])[0]
        else:
            client_socket.send(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            client_socket.close()
            return

        # Connect to target
        try:
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((addr, port))

            # Send success response
            client_socket.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')

            # Relay data
            def relay(src, dst):
                try:
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.send(data)
                except:
                    pass
                finally:
                    src.close()
                    dst.close()

            threading.Thread(target=relay, args=(client_socket, remote_socket), daemon=True).start()
            threading.Thread(target=relay, args=(remote_socket, client_socket), daemon=True).start()

        except Exception as e:
            client_socket.send(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            client_socket.close()

    except Exception as e:
        client_socket.close()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1080
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)

    print(f"SOCKS5 proxy listening on port {port}")

    try:
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client,), daemon=True).start()
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        server.close()

if __name__ == '__main__':
    main()
EOF

    chmod +x /tmp/simple-socks5.py

    echo "Starting SOCKS5 proxy in namespace..."
    ip netns exec "$NAMESPACE" python3 /tmp/simple-socks5.py $INTERNAL_SOCKS5_PORT &
    SOCKS5_PID=$!
    echo $SOCKS5_PID > "/tmp/mullvad-socks5-$SERVER.pid"

    # Save main script PID for stop command
    echo $ > "/tmp/mullvad-main-$SERVER.pid"

    echo "Waiting for proxy to start..."
    sleep 2

    # Create a veth pair to connect namespace to host
    echo "Setting up namespace connectivity..."

    # Test namespace before veth creation
    echo "Testing namespace before veth setup..."
    ip netns exec "$NAMESPACE" echo "Pre-veth test successful" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Namespace inaccessible before veth setup"
        cleanup_existing
        return 1
    fi

    echo "Creating veth pair: $VETH_HOST <-> $VETH_NS"
    ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create veth pair"
        cleanup_existing
        return 1
    fi

    echo "Moving $VETH_NS to namespace..."
    ip link set "$VETH_NS" netns "$NAMESPACE"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to move veth interface to namespace"
        cleanup_existing
        return 1
    fi

    # Test namespace after moving veth
    echo "Testing namespace after veth move..."
    ip netns exec "$NAMESPACE" echo "Post-veth-move test successful" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Namespace became inaccessible after moving veth interface"
        cleanup_existing
        return 1
    fi

    echo "Configuring host veth interface..."
    ip addr add "192.168.100.1/24" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    echo "Configuring namespace veth interface..."
    ip netns exec "$NAMESPACE" ip addr add "192.168.100.2/24" dev "$VETH_NS"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to configure namespace veth interface"
        cleanup_existing
        return 1
    fi

    ip netns exec "$NAMESPACE" ip link set "$VETH_NS" up
    if [ $? -ne 0 ]; then
        echo "Error: Failed to bring up namespace veth interface"
        cleanup_existing
        return 1
    fi

    # Forward SOCKS5 traffic from host to namespace
    echo "Setting up port forwarding..."
    socat TCP-LISTEN:$EXTERNAL_SOCKS5_PORT,fork,bind=127.0.0.1 TCP:192.168.100.2:$INTERNAL_SOCKS5_PORT &
    SOCAT_PID=$!
    echo $SOCAT_PID > "/tmp/mullvad-socat-$SERVER.pid"

    # Test if the interface is working
    echo "Testing WireGuard connection..."
    ip netns exec "$NAMESPACE" timeout 10 ping -c 1 "$DNS_SERVER" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✓ WireGuard connection established successfully"
    else
        echo "⚠ Warning: WireGuard connection test failed - proxy may not work correctly"
    fi

    echo ""
    echo "Proxy setup complete for server: $SERVER"
    echo "SOCKS5 proxy available at: 127.0.0.1:$EXTERNAL_SOCKS5_PORT"
    echo "Config: $CONFIG_FILE"
    echo "Endpoint: $ENDPOINT"
    echo ""
    echo "Test with: curl --socks5-hostname 127.0.0.1:$EXTERNAL_SOCKS5_PORT https://am.i.mullvad.net"

    # Keep the script running to maintain namespace reference
    echo "Maintaining namespace... (PID: $)"
    trap 'echo "Received termination signal, cleaning up..."; cleanup_existing; exit 0' TERM INT

    # Wait for background processes and keep namespace alive
    while kill -0 $SOCKS5_PID 2>/dev/null && kill -0 $SOCAT_PID 2>/dev/null; do
        sleep 5
    done

    echo "Background processes terminated, cleaning up..."
    cleanup_existing
}

cleanup_namespace() {
    echo "Cleaning up server: $SERVER"
    # Parse config to get proper names before cleanup
    parse_wg_config "$CONFIG_FILE" 2>/dev/null
    set_port_based_names
    cleanup_existing
}

# Function to show status
show_status() {
    echo "=== Mullvad Namespace Status ($SERVER) ==="
    echo "Config file: $CONFIG_FILE"

    # Parse config to get port info and set names
    parse_wg_config "$CONFIG_FILE" 2>/dev/null
    set_port_based_names

    echo "External SOCKS5 port: $EXTERNAL_SOCKS5_PORT"
    echo "Internal SOCKS5 port: $INTERNAL_SOCKS5_PORT"
    echo "Namespace: $NAMESPACE"
    echo "Interface: $INTERFACE"

    echo "Namespace exists: $(ip netns list | grep -q "$NAMESPACE" && echo "Yes" || echo "No")"

    if ip netns list | grep -q "$NAMESPACE"; then
        echo "WireGuard interface:"
        ip netns exec "$NAMESPACE" wg show 2>/dev/null || echo "  Not configured"

        echo "IP addresses:"
        ip netns exec "$NAMESPACE" ip addr show "$INTERFACE" 2>/dev/null | grep inet || echo "  None configured"

        echo "Routes:"
        ip netns exec "$NAMESPACE" ip route show 2>/dev/null || echo "  None configured"

        echo "Main script:"
        if [ -f "/tmp/mullvad-main-$SERVER.pid" ] && kill -0 $(cat "/tmp/mullvad-main-$SERVER.pid") 2>/dev/null; then
            echo "  Running (PID: $(cat "/tmp/mullvad-main-$SERVER.pid"))"
        else
            echo "  Not running"
        fi

        echo "SOCKS5 proxy:"
        if [ -f "/tmp/mullvad-socks5-$SERVER.pid" ] && kill -0 $(cat "/tmp/mullvad-socks5-$SERVER.pid") 2>/dev/null; then
            echo "  Running in namespace (PID: $(cat "/tmp/mullvad-socks5-$SERVER.pid"))"
        else
            echo "  Not running in namespace"
        fi

        echo "Port forwarder:"
        if [ -f "/tmp/mullvad-socat-$SERVER.pid" ] && kill -0 $(cat "/tmp/mullvad-socat-$SERVER.pid") 2>/dev/null; then
            echo "  Running (PID: $(cat "/tmp/mullvad-socat-$SERVER.pid"))"
        else
            echo "  Not running"
        fi

        echo "Veth pair:"
        ip link show "$VETH_HOST" 2>/dev/null | grep -q "state UP" && echo "  $VETH_HOST: UP" || echo "  $VETH_HOST: DOWN/Missing"
        ip netns exec "$NAMESPACE" ip link show "$VETH_NS" 2>/dev/null | grep -q "state UP" && echo "  $VETH_NS: UP" || echo "  $VETH_NS: DOWN/Missing"
    fi
}

case "$1" in
    start)
        setup_namespace
        ;;
    stop)
        cleanup_namespace
        ;;
    restart)
        cleanup_namespace
        sleep 2
        setup_namespace
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status} [server-name]"
        echo "Example: $0 start no-osl-wg-001"
        echo "Config files should be in /etc/mullvad-socks5-proxy/[server-name].conf"
        exit 1
        ;;
esac