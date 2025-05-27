#!/bin/bash

if [ "$EUID" -ne 0 ]; then 
    echo "This script must be run as root"
    exit 1
fi

# Store the script's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install_wireguard() {
    echo "Installing WireGuard and dependencies..."
    apt update > /dev/null 2>&1
    apt install -y wireguard qrencode iptables-persistent > /dev/null 2>&1
    echo "Installation complete"
}

setup_server() {
    echo "Setting up WireGuard server..."
    mkdir -p /etc/wireguard
    cd /etc/wireguard
    chmod 700 /etc/wireguard
    
    # Enable IP forwarding for both IPv4 and IPv6
    cat > /etc/sysctl.d/99-wireguard.conf << EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -p /etc/sysctl.d/99-wireguard.conf > /dev/null 2>&1
    
    # Configure firewall rules with SSH protection
    echo "Configuring firewall rules..."
    
    # Clear existing rules
    iptables -F
    iptables -t nat -F
    ip6tables -F
    ip6tables -t nat -F
    
    # Essential INPUT rules to preserve SSH and basic connectivity
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 2222 -j ACCEPT  # In case SSH is on custom port
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT  # WireGuard port
    iptables -A INPUT -p icmp -j ACCEPT
    
    # IPv6 INPUT rules
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 2222 -j ACCEPT
    ip6tables -A INPUT -p udp --dport 51820 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    
    # WireGuard FORWARD rules
    iptables -A FORWARD -i wg0 -j ACCEPT
    iptables -A FORWARD -o wg0 -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    ip6tables -A FORWARD -i wg0 -j ACCEPT
    ip6tables -A FORWARD -o wg0 -j ACCEPT
    ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Detect the correct network interface
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    SERVER_IPV4=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1)
    
    echo "Using network interface: ${INTERFACE}"
    echo "Server IP: ${SERVER_IPV4}"
    
    # NAT rules for WireGuard traffic
    iptables -t nat -A POSTROUTING -o ${INTERFACE} -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o ${INTERFACE} -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -o ${INTERFACE} -j MASQUERADE
    
    # Set default policies (optional - be careful with DROP)
    # iptables -P INPUT DROP
    # iptables -P FORWARD DROP
    # ip6tables -P INPUT DROP
    # ip6tables -P FORWARD DROP
    
    # Generate server keys
    echo "Generating server keys..."
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    chmod 600 /etc/wireguard/server_private.key
    
    SERVER_PRIVATE_KEY=$(cat /etc/wireguard/server_private.key)
    
    # Create WireGuard server configuration
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${SERVER_PRIVATE_KEY}
Address = 10.66.66.1/24, fd00:1234:5678:9abc::1/64
ListenPort = 51820
PostUp = iptables -I INPUT -p udp --dport 51820 -j ACCEPT; iptables -I FORWARD -i wg0 -j ACCEPT; iptables -I FORWARD -o wg0 -j ACCEPT; iptables -t nat -I POSTROUTING -o ${INTERFACE} -j MASQUERADE; ip6tables -I FORWARD -i wg0 -j ACCEPT; ip6tables -I FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -I POSTROUTING -o ${INTERFACE} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport 51820 -j ACCEPT; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${INTERFACE} -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -D FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${INTERFACE} -j MASQUERADE
EOF
    
    # Save iptables rules to persist after reboot
    echo "Saving firewall rules..."
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save > /dev/null 2>&1
    else
        # Fallback for systems without netfilter-persistent
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi
    
    # Enable and start WireGuard
    echo "Enabling and starting WireGuard service..."
    systemctl enable wg-quick@wg0 > /dev/null 2>&1
    systemctl restart wg-quick@wg0 > /dev/null 2>&1
    
    # Verify setup
    echo "Verifying WireGuard setup..."
    sleep 2
    if systemctl is-active --quiet wg-quick@wg0; then
        echo "✓ WireGuard is running successfully"
        echo "✓ Server IP: ${SERVER_IPV4}"
        echo "✓ Interface: ${INTERFACE}"
        echo "✓ WireGuard listening on port 51820"
    else
        echo "✗ Error: WireGuard failed to start"
        echo "Check logs with: journalctl -xeu wg-quick@wg0"
        return 1
    fi
    
    echo "Server setup complete"
}

add_mobile_client() {
    echo "Adding new mobile client..."
    read -p "Enter client number: " CLIENT_NUM

    if ! [[ "$CLIENT_NUM" =~ ^[0-9]+$ ]]; then
        echo "Error: Please enter a valid number"
        return 1
    fi

    # Check if client number already exists
    if grep -q "10.66.66.${CLIENT_NUM}/32" /etc/wireguard/wg0.conf 2>/dev/null || \
       grep -q "fd00:1234:5678:9abc::${CLIENT_NUM}/128" /etc/wireguard/wg0.conf 2>/dev/null; then
        echo "Error: Client ${CLIENT_NUM} already exists"
        return 1
    fi

    echo "Choose client IP version:"
    echo "1. IPv4 only"
    echo "2. IPv6 only"
    echo "3. Both IPv4 and IPv6"
    read -p "Enter your choice [1-3]: " ip_choice

    case $ip_choice in
        1)
            CLIENT_ADDRESS="10.66.66.${CLIENT_NUM}/24"
            CLIENT_ALLOWED_IPS="10.66.66.${CLIENT_NUM}/32"
            DNS="8.8.8.8"
            read -p "Enter server's public IPv4 address: " SERVER_ENDPOINT
            ENDPOINT="${SERVER_ENDPOINT}:51820"
            ;;
        2)
            CLIENT_ADDRESS="fd00:1234:5678:9abc::${CLIENT_NUM}/64"
            CLIENT_ALLOWED_IPS="fd00:1234:5678:9abc::${CLIENT_NUM}/128"
            DNS="2606:4700:4700::1111"
            read -p "Enter server's public IPv6 address: " SERVER_ENDPOINT
            ENDPOINT="[${SERVER_ENDPOINT}]:51820"
            ;;
        3)
            CLIENT_ADDRESS="10.66.66.${CLIENT_NUM}/24, fd00:1234:5678:9abc::${CLIENT_NUM}/64"
            CLIENT_ALLOWED_IPS="10.66.66.${CLIENT_NUM}/32, fd00:1234:5678:9abc::${CLIENT_NUM}/128"
            DNS="8.8.8.8, 2606:4700:4700::1111"
            read -p "Enter server's public IPv4 address: " SERVER_ENDPOINT4
            read -p "Enter server's public IPv6 address: " SERVER_ENDPOINT6
            # You can choose which to use as default, or let user pick
            ENDPOINT="[${SERVER_ENDPOINT6}]:51820"
            ;;
        *)
            echo "Invalid choice"
            return 1
            ;;
    esac

    mkdir -p /etc/wireguard/mobile_clients
    mkdir -p "${SCRIPT_DIR}/clients"

    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)
    SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)

    # Client configuration
    CONFIG_CONTENT="[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_ADDRESS}
DNS = ${DNS}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${ENDPOINT}
PersistentKeepalive = 25"

    # Save config files
    echo "$CONFIG_CONTENT" > "/etc/wireguard/mobile_clients/mobile_${CLIENT_NUM}.conf"
    echo "$CONFIG_CONTENT" > "${SCRIPT_DIR}/clients/mobile_${CLIENT_NUM}.conf"

    # Add peer to server configuration
    cat >> /etc/wireguard/wg0.conf << EOF

[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${CLIENT_ALLOWED_IPS}
EOF

    echo "Generating QR code for client ${CLIENT_NUM}..."
    echo "Scan this QR code with your WireGuard mobile app:"
    echo "================================================"
    qrencode -t ansiutf8 < "${SCRIPT_DIR}/clients/mobile_${CLIENT_NUM}.conf"
    echo "================================================"

    # Restart WireGuard to apply new peer
    systemctl restart wg-quick@wg0 > /dev/null 2>&1

    echo "✓ Client ${CLIENT_NUM} added successfully"
    echo "Configuration files saved in:"
    echo "1. /etc/wireguard/mobile_clients/mobile_${CLIENT_NUM}.conf"
    echo "2. ${SCRIPT_DIR}/clients/mobile_${CLIENT_NUM}.conf"
}

show_status() {
    echo "=== WireGuard Status ==="
    echo "Service status:"
    systemctl status wg-quick@wg0 --no-pager -l
    echo ""
    echo "Active connections:"
    wg show
    echo ""
    echo "Server configuration:"
    cat /etc/wireguard/wg0.conf
}

show_menu() {
    clear
    echo "=== WireGuard Setup Menu ==="
    echo "1. Install WireGuard"
    echo "2. Setup WireGuard Server"
    echo "3. Add Mobile Client"
    echo "4. Show Status"
    echo "5. Exit"
    echo "=========================="
}

# Main menu loop
while true; do
    show_menu
    read -p "Enter your choice [1-5]: " choice
    
    case $choice in
        1)
            install_wireguard
            read -p "Press Enter to continue..."
            ;;
        2)
            setup_server
            read -p "Press Enter to continue..."
            ;;
        3)
            add_mobile_client
            read -p "Press Enter to continue..."
            ;;
        4)
            show_status
            read -p "Press Enter to continue..."
            ;;
        5)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            read -p "Press Enter to continue..."
            ;;
    esac
done
