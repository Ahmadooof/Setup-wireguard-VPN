#!/bin/bash

if [ "$EUID" -ne 0 ]; then 
    echo "This script must be run as root"
    exit 1
fi

# Store the script's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install_wireguard() {
    echo "Installing WireGuard and dependencies..."
    DEBIAN_FRONTEND=noninteractive apt update
    DEBIAN_FRONTEND=noninteractive apt install -y wireguard qrencode iptables-persistent
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
    
    # Detect the correct network interface
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then
        # Fallback method if the first method fails
        INTERFACE=$(ip link show | grep -v lo | grep -v wg | grep -v docker | grep -v veth | grep -v br- | grep -v "LOOPBACK" | grep "state UP" | head -n 1 | awk -F: '{print $2}' | tr -d ' ')
    fi
    
    # If still empty, ask the user
    if [ -z "$INTERFACE" ]; then
        echo "Could not automatically detect network interface."
        echo "Available interfaces:"
        ip -o link show | grep -v LOOPBACK | awk -F': ' '{print $2}'
        read -p "Please enter your network interface name: " INTERFACE
    fi
    
    SERVER_IPV4=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1)
    SERVER_IPV6=$(ip -6 addr show | grep -oP '(?<=inet6\s)[\da-f:]+' | grep -v '^::1' | grep -v '^fe80' | head -n 1)
    
    echo "Using network interface: ${INTERFACE}"
    echo "Server IPv4: ${SERVER_IPV4}"
    if [ -n "$SERVER_IPV6" ]; then
        echo "Server IPv6: ${SERVER_IPV6}"
    fi
    
    # Generate server keys
    echo "Generating server keys..."
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    chmod 600 /etc/wireguard/server_private.key
    
    SERVER_PRIVATE_KEY=$(cat /etc/wireguard/server_private.key)
    
    # Create WireGuard server configuration with explicit interface name
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${SERVER_PRIVATE_KEY}
Address = 10.66.66.1/24, fd00:1234:5678:9abc::1/64
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o ${INTERFACE} -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -A FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -s fd00:1234:5678:9abc::/64 -o ${INTERFACE} -j MASQUERADE; iptables -A OUTPUT -o wg0 -p udp --dport 53 -j ACCEPT; ip6tables -A OUTPUT -o wg0 -p udp --dport 53 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o ${INTERFACE} -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -D FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -s fd00:1234:5678:9abc::/64 -o ${INTERFACE} -j MASQUERADE; iptables -D OUTPUT -o wg0 -p udp --dport 53 -j ACCEPT; ip6tables -D OUTPUT -o wg0 -p udp --dport 53 -j ACCEPT
EOF
    
    # Save iptables rules to persist after reboot
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save > /dev/null 2>&1
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
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
            DNS="1.1.1.2, 9.9.9.9"
            read -p "Enter server's public IPv4 address: " SERVER_ENDPOINT
            ENDPOINT="${SERVER_ENDPOINT}:51820"
            ;;
        2)
            CLIENT_ADDRESS="fd00:1234:5678:9abc::${CLIENT_NUM}/64"
            CLIENT_ALLOWED_IPS="fd00:1234:5678:9abc::${CLIENT_NUM}/128"
            DNS="2606:4700:4700::1112, 2620:fe::9"
            read -p "Enter server's public IPv6 address: " SERVER_ENDPOINT
            ENDPOINT="[${SERVER_ENDPOINT}]:51820"
            ;;
        3)
            CLIENT_ADDRESS="10.66.66.${CLIENT_NUM}/24, fd00:1234:5678:9abc::${CLIENT_NUM}/64"
            CLIENT_ALLOWED_IPS="10.66.66.${CLIENT_NUM}/32, fd00:1234:5678:9abc::${CLIENT_NUM}/128"
            DNS="1.1.1.2, 9.9.9.9, 2606:4700:4700::1112, 2620:fe::9"
            read -p "Enter server's public IPv4 address: " SERVER_ENDPOINT4
            # Use IPv4 as the primary endpoint for better compatibility
            ENDPOINT="${SERVER_ENDPOINT4}:51820"
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

list_clients() {
    echo "=== WireGuard Clients ==="
    if [ -f /etc/wireguard/wg0.conf ]; then
        echo "Client list:"
        grep -n "\[Peer\]" /etc/wireguard/wg0.conf | while read -r line; do
            line_num=$(echo "$line" | cut -d: -f1)
            next_line=$((line_num + 2))
            ip_line=$(sed -n "${next_line}p" /etc/wireguard/wg0.conf)
            client_ip=$(echo "$ip_line" | grep -oP 'AllowedIPs\s*=\s*\K[^,]+')
            client_num=$(echo "$client_ip" | grep -oP '10\.66\.66\.(\d+)' | cut -d. -f4 | cut -d/ -f1)
            if [ -n "$client_num" ]; then
                echo "Client $client_num: $client_ip"
            else
                client_num=$(echo "$client_ip" | grep -oP 'fd00:1234:5678:9abc::(\d+)' | cut -d: -f8 | cut -d/ -f1)
                if [ -n "$client_num" ]; then
                    echo "Client $client_num: $client_ip (IPv6)"
                fi
            fi
        done
    else
        echo "WireGuard configuration not found"
    fi
}

remove_client() {
    echo "=== Remove WireGuard Client ==="
    list_clients
    read -p "Enter client number to remove: " CLIENT_NUM
    
    if ! [[ "$CLIENT_NUM" =~ ^[0-9]+$ ]]; then
        echo "Error: Please enter a valid number"
        return 1
    fi
    
    # Find and remove client from config
    if [ -f /etc/wireguard/wg0.conf ]; then
        # Create temp file
        TEMP_FILE=$(mktemp)
        
        # Find the start line of the peer section for this client
        START_LINE=$(grep -n "AllowedIPs.*10\.66\.66\.${CLIENT_NUM}/32\|AllowedIPs.*fd00:1234:5678:9abc::${CLIENT_NUM}/128" /etc/wireguard/wg0.conf | cut -d: -f1)
        
        if [ -z "$START_LINE" ]; then
            echo "Error: Client ${CLIENT_NUM} not found"
            rm "$TEMP_FILE"
            return 1
        fi
        
        # Find the peer section start (2 lines before AllowedIPs)
        PEER_START=$((START_LINE - 2))
        
        # Remove the peer section (3 lines total)
        sed -e "${PEER_START},${START_LINE}d" /etc/wireguard/wg0.conf > "$TEMP_FILE"
        
        # Replace the original file
        cat "$TEMP_FILE" > /etc/wireguard/wg0.conf
        rm "$TEMP_FILE"
        
        # Remove client config files
        rm -f "/etc/wireguard/mobile_clients/mobile_${CLIENT_NUM}.conf"
        rm -f "${SCRIPT_DIR}/clients/mobile_${CLIENT_NUM}.conf"
        
        # Restart WireGuard
        systemctl restart wg-quick@wg0 > /dev/null 2>&1
        
        echo "✓ Client ${CLIENT_NUM} removed successfully"
    else
        echo "WireGuard configuration not found"
    fi
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
    echo "4. List Clients"
    echo "5. Remove Client"
    echo "6. Show Status"
    echo "7. Exit"
    echo "=========================="
}

# Main menu loop
while true; do
    show_menu
    read -p "Enter your choice [1-7]: " choice
    
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
            list_clients
            read -p "Press Enter to continue..."
            ;;
        5)
            remove_client
            read -p "Press Enter to continue..."
            ;;
        6)
            show_status
            read -p "Press Enter to continue..."
            ;;
        7)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            read -p "Press Enter to continue..."
            ;;
    esac
done
