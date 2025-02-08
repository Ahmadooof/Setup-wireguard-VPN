#!/bin/bash

# Function to update the system
function update_system() {
    echo "Updating the system..."
    apt update
    apt upgrade -y
}

# Function to install WireGuard
function install_wireguard() {
    echo "Installing WireGuard..."
    apt install -y wireguard
}

# Function to upgrade WireGuard to the latest version
function upgrade_wireguard() {
    echo "Upgrading WireGuard to the latest version..."
    add-apt-repository -y ppa:wireguard/wireguard
    apt update
    apt upgrade -y wireguard
}

# Function to generate private and public keys
function generate_keys() {
    echo "Generating private and public keys..."
    umask 077
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey | tee /etc/wireguard/publickey
    chmod 600 /etc/wireguard/privatekey
}

# Function to install QR Code package
function install_qrcode() {
    apt install -y qrencode
}

# Function to configure WireGuard on the server
function configure_wireguard() {
    echo "Configuring WireGuard server..."
    cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.1/24
PrivateKey = $(cat /etc/wireguard/privatekey)
SaveConfig = true
ListenPort = 51820
MTU = 1420        # Increased MTU to avoid fragmentation
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PersistentKeepalive = 25
EOF
    chmod 600 /etc/wireguard/wg0.conf
}

# Function to enable IP forwarding
function enable_ip_forwarding() {
    echo "Enabling IP forwarding..."
    echo "net.ipv4.ip_forward=1" | tee -a /etc/sysctl.conf
    sysctl -p
}

# Function to enable TCP optimizations
function enable_tcp_optimizations() {
    echo "Enabling TCP optimizations..."
    sysctl -w net.ipv4.tcp_window_scaling=1
    sysctl -w net.ipv4.tcp_rmem="4096 87380 4194304"
    sysctl -w net.ipv4.tcp_wmem="4096 87380 4194304"
    sysctl -w net.core.rmem_max=16777216
    sysctl -w net.core.wmem_max=16777216
    sysctl -p
}

# Function to enable crypto hardware acceleration if supported
function enable_crypto_acceleration() {
    echo "Checking and enabling crypto hardware acceleration..."
    if lscpu | grep -q avx2; then
        echo "AVX2 supported, optimizing WireGuard performance..."
        modprobe wireguard
    else
        echo "No AVX2 support. Skipping crypto acceleration."
    fi
}

# Function to configure firewall with optimizations for better speed
function configure_firewall() {
    echo "Configuring firewall with optimizations..."
    ufw allow 22
    ufw allow 51820/udp
    ufw default allow FORWARD
    ufw enable
    ufw allow OpenSSH

    # Tighten firewall rules for better performance
    ufw logging off
    ufw default deny incoming
    ufw default allow outgoing
}

# Function to configure WireGuard client with higher MTU and optimizations
function configure_client() {
    echo "Configuring WireGuard client..."
    cat << EOF > /etc/wireguard/client.conf
[Interface]
PrivateKey = $(cat /etc/wireguard/privatekey)
Address = 10.0.0.2/24
MTU = 1420        # Ensure MTU is consistent between server and client

[Peer]
PublicKey = $(cat /etc/wireguard/publickey)
AllowedIPs = 0.0.0.0/0
Endpoint = $(curl -s ifconfig.me):51820
PersistentKeepalive = 25
EOF
    chmod 600 /etc/wireguard/client.conf
}

# Function to restart WireGuard with updated configuration
function restart_wireguard() {
    echo "Restarting WireGuard..."
    wg-quick down wg0
    wg-quick up wg0
}

# Function to show WireGuard status
function show_wireguard_status() {
    echo "WireGuard Status:"
    systemctl status wg-quick@wg0.service --no-pager
}

# Function to list connected clients
function list_connected_clients() {
    echo "Connected Clients:"
    wg show wg0
}

# Function to monitor client connections
function monitor_client_connections() {
    echo "Monitoring client connections..."
    echo "Displaying connection stats for each peer (packets sent, received, and latest handshake):"
    wg show wg0
}

# Function to add a new peer to the WireGuard configuration
function add_peer() {
    wg-quick up wg0
    echo "Adding a new peer to the WireGuard configuration..."
    privatekey=$(wg genkey)
    publickey=$(echo $privatekey | wg pubkey)

    read -p "Enter the IP address for the new peer (e.g., 10.0.0.5): " ip

    cat << EOF > /etc/wireguard/client_$ip.conf
[Interface]
PrivateKey = $privatekey
Address = $ip/24

[Peer]
PublicKey = $(cat /etc/wireguard/publickey)
AllowedIPs = 0.0.0.0/0
Endpoint = $(curl -s ifconfig.me):51820
PersistentKeepalive = 25

EOF

    wg set wg0 peer $publickey allowed-ips $ip
    qrencode -t ansiutf8 < /etc/wireguard/client_$ip.conf
}

# Function to enable AVX2 if supported
function enable_avx2() {
    echo "Checking for AVX2 support..."
    if grep -q avx2 /proc/cpuinfo; then
        echo "AVX2 is supported. Optimizing WireGuard..."
        modprobe wireguard
    else
        echo "AVX2 is not supported on this CPU. Skipping optimization."
    fi
}

# Main script execution
echo "WireGuard Server Setup"
echo "----------------------"
echo "Please select an option:"
echo "1. Update the system"
echo "2. Install WireGuard"
echo "3. Generate keys"
echo "4. Configure WireGuard"
echo "5. Enable IP forwarding"
echo "6. Enable TCP optimizations"
echo "7. Enable Crypto acceleration (AVX2)"
echo "8. Configure firewall"
echo "9. Configure WireGuard Client"
echo "a. Restart WireGuard"
echo "b. Show WireGuard Status"
echo "c. List Connected Clients"
echo "d. Monitor Client Connections (Packets Sent/Received)"
echo "e. Add a peer"
echo "f. Install QR Code package"
echo "g. Upgrade WireGuard to latest version"

read -p "Enter the option number: " option

# Main script execution based on user input
case $option in
    1) update_system ;;
    2) install_wireguard ;;
    3) generate_keys ;;
    4) configure_wireguard ;;
    5) enable_ip_forwarding ;;
    6) enable_tcp_optimizations ;;
    7) enable_crypto_acceleration ;;
    8) configure_firewall ;;
    9) configure_client ;;
    a) restart_wireguard ;;
    b) show_wireguard_status ;;
    c) list_connected_clients ;;
    d) monitor_client_connections ;;
    e) add_peer ;;
    f) install_qrcode ;;
    g) upgrade_wireguard ;;
    *) echo "Invalid option selected" ;;
esac
