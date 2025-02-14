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
    apt install -y wireguard qrencode > /dev/null 2>&1
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
    
    # Clear existing iptables rules
    echo "Configuring firewall rules..."
    iptables -F
    iptables -t nat -F
    ip6tables -F
    ip6tables -t nat -F
    
    # Add IPv4 rules
    iptables -A FORWARD -i wg0 -j ACCEPT
    iptables -A FORWARD -o wg0 -j ACCEPT
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE
    
    # Add IPv6 rules
    ip6tables -A FORWARD -i wg0 -j ACCEPT
    ip6tables -A FORWARD -o wg0 -j ACCEPT
    ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    
    # Generate server keys
    echo "Generating server keys..."
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    chmod 600 /etc/wireguard/server_private.key
    
    SERVER_PRIVATE_KEY=$(cat /etc/wireguard/server_private.key)
    
    # Detect the correct network interface
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    SERVER_IPV4=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1)
    
    echo "Using network interface: ${INTERFACE}"
    
    # Updated server configuration with both IPv4 and IPv6 and comprehensive rules
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${SERVER_PRIVATE_KEY}
Address = 10.66.66.1/24, fd00:1234:5678:9abc::1/64
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${INTERFACE} -j MASQUERADE; iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o ${INTERFACE} -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -A FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${INTERFACE} -j MASQUERADE; iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o ${INTERFACE} -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -D FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${INTERFACE} -j MASQUERADE
EOF
    
    # Enable and start WireGuard
    echo "Enabling and starting WireGuard service..."
    systemctl enable wg-quick@wg0 > /dev/null 2>&1
    systemctl restart wg-quick@wg0 > /dev/null 2>&1
    
    # Verify setup
    echo "Verifying WireGuard setup..."
    if systemctl is-active --quiet wg-quick@wg0; then
        echo "WireGuard is running successfully"
        echo "Server IP: ${SERVER_IPV4}"
        echo "Interface: ${INTERFACE}"
    else
        echo "Error: WireGuard failed to start"
        echo "Check logs with: journalctl -xeu wg-quick@wg0"
        return 1
    fi
    
    # Save iptables rules to persist after reboot
    echo "Saving firewall rules..."
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save > /dev/null 2>&1
    else
        apt-get install -y iptables-persistent > /dev/null 2>&1
        netfilter-persistent save > /dev/null 2>&1
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
    
    mkdir -p /etc/wireguard/mobile_clients
    mkdir -p "${SCRIPT_DIR}/clients"
    
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)
    SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)
    SERVER_IPV4=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1)
    
    # Updated client IP addresses to include both IPv4 and IPv6
    CLIENT_IPV4="10.66.66.${CLIENT_NUM}/24"
    CLIENT_IPV6="fd00:1234:5678:9abc::${CLIENT_NUM}/64"
    
    # Updated client configuration with both IPv4 and IPv6
    CONFIG_CONTENT="[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_IPV4}, ${CLIENT_IPV6}
DNS = 8.8.8.8, 2606:4700:4700::1111

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${SERVER_IPV4}:51820
PersistentKeepalive = 25"

    # Save config in WireGuard directory
    echo "$CONFIG_CONTENT" > "/etc/wireguard/mobile_clients/mobile_${CLIENT_NUM}.conf"
    
    # Save config in script directory
    echo "$CONFIG_CONTENT" > "${SCRIPT_DIR}/clients/mobile_${CLIENT_NUM}.conf"
    
    # Updated peer configuration in server config with both IPv4 and IPv6
    cat >> /etc/wireguard/wg0.conf << EOF

[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = 10.66.66.${CLIENT_NUM}/32, fd00:1234:5678:9abc::${CLIENT_NUM}/128
EOF
    
    echo "Generating QR code for client ${CLIENT_NUM}..."
    qrencode -t ansiutf8 < "${SCRIPT_DIR}/clients/mobile_${CLIENT_NUM}.conf"
    
    systemctl restart wg-quick@wg0 > /dev/null 2>&1
    
    echo "Client ${CLIENT_NUM} added successfully"
    echo "Configuration files saved in:"
    echo "1. /etc/wireguard/mobile_clients/mobile_${CLIENT_NUM}.conf"
    echo "2. ${SCRIPT_DIR}/clients/mobile_${CLIENT_NUM}.conf"
}

show_menu() {
    clear
    echo "=== WireGuard Setup Menu ==="
    echo "1. Install WireGuard"
    echo "2. Setup WireGuard Server"
    echo "3. Add Mobile Client"
    echo "4. Exit"
    echo "=========================="
}

while true; do
    show_menu
    read -p "Enter your choice [1-4]: " choice
    
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
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            read -p "Press Enter to continue..."
            ;;
    esac
done
