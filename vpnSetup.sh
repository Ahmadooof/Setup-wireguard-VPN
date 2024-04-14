#!/bin/bash

function update_system() {
    echo "Updating the system..."
    sudo apt update
    sudo apt upgrade -y
}

function install_wireguard() {
    echo "Installing WireGuard..."
    sudo apt install -y wireguard
}

function generate_keys() {
    echo "Generating private and public keys..."
    umask 077
    wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey
}

function installQRCode(){
    sudo apt install qrencode
}

function configure_wireguard() {
    echo "Configuring WireGuard server..."
    sudo touch /etc/wireguard/wg0.conf
    sudo chmod 600 /etc/wireguard/wg0.conf

    cat << EOF | sudo tee /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.1/24
PrivateKey = $(sudo cat /etc/wireguard/privatekey)
SaveConfig = true
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

EOF
}



function enable_ip_forwarding() {
    echo "Enabling IP forwarding..."
    sudo sed -i '/^#net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
    sudo sysctl -p
}
function deleteAndRecreateConfig() {
    sudo wg-quick down wg0
    sudo chmod -R 777 /etc/wireguard
    sudo rm /etc/wireguard/wg0.conf
    configure_wireguard
    sudo wg-quick up wg0
}

# stop wireguard before editing /etc/wireguard/wg0
function Stop_wireguard() {
    echo "Stop WireGuard..."
    sudo systemctl stop wg-quick@wg0.service
    sudo wg-quick down wg0
    sudo systemctl status wg-quick@wg0.service
    sudo chmod -R 777 /etc/wireguard
}

function Restart_wireguard() {
    echo "Starting WireGuard..."
    sudo systemctl stop wg-quick@wg0.service
    sudo wg-quick down wg0
    sudo systemctl start wg-quick@wg0.service
    sudo wg-quick up wg0
    sudo systemctl enable --now wg-quick@wg0
    sudo systemctl status wg-quick@wg0.service
    sudo chmod -R 777 /etc/wireguard
}

function display_public_key() {
    echo "Server's public key:"
    sudo cat /etc/wireguard/publickey
}

function configure_firewall() {
    echo "Configuring firewall..."
    sudo ufw allow 22
    sudo ufw allow 51820/udp
    sudo ufw enable
    sudo ufw allow OpenSSH
}

function add_peer() {
    echo "Adding a new peer to the WireGuard configuration..."
    privatekey=$(wg genkey)
    publickey=$(echo $privatekey | wg pubkey)
    umask 077
    # echo "$privatekey" > privatekey
    # echo "$publickey" > publickey

    read -p "Enter the IP address for the new peer on the WireGuard network (e.g., 10.0.0.5): " ip
    # read -p "Enter the allowed IP addresses for the new peer (e.g., 0.0.0.0): " allowed_ips

    cat << EOF > wg1.conf

[Interface]
PrivateKey = $privatekey 
Address = $ip/24

[Peer]
PublicKey = $(sudo cat /etc/wireguard/publickey)
AllowedIPs = 0.0.0.0/0
Endpoint = $(curl -s ifconfig.me):51820

EOF

    sudo wg set wg0 peer $publickey allowed-ips $ip
    sudo systemctl restart wg-quick@wg0
    qrencode -t ansiutf8 < wg1.conf
    sudo rm wg1.conf
}

function giveFullAccessWireguardFolder() {
    sudo chmod -R 777 /etc/wireguard
}
function giveNoAccessWireguardFolder() {
    sudo chmod -R 000 /etc/wireguard
}

# Prompt user for input
echo "WireGuard Server Setup"
echo "----------------------"
echo "Please select an option:"
echo "1. Update the system"
echo "2. Install WireGuard"
echo "3. Generate keys"
echo "4. Configure WireGuard"
echo "5. Enable IP forwarding"
echo "6. Restart WireGuard"
echo "7. Delete And Recreate Config"
echo "8. Display server's public key"
echo "9. Configure firewall"
echo "a. Add peer"
echo "b. give Full Access Wireguard Folder"
echo "c. give No Access Wireguard Folder"
echo "d. stop wireguard"
echo "e. check who access"
echo "f. install QR code"

read -p "Enter the option number: " option

# Main script execution based on user input
case $option in
    1) update_system ;;
    2) install_wireguard ;;
    3) generate_keys ;;
    4) configure_wireguard ;;
    5) enable_ip_forwarding ;;
    6) Restart_wireguard ;;
    7) deleteAndRecreateConfig ;;
    8) display_public_key ;;
    9) configure_firewall ;;
    a) add_peer ;;
    b) giveFullAccessWireguardFolder ;;
    c) giveNoAccessWireguardFolder ;;
    d) Stop_wireguard ;;
    e) checkWhoAccess ;;
    f) installQRCode ;;
    *) echo "Invalid option selected" ;;
esac






#sudo systemctl start wg-quick@wg0.service
# sudo systemctl status wg-quick@wg0.service