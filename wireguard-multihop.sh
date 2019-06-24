#!/bin/bash
## THIS IS DEV, IT DOSENT WORK.	
# https://github.com/LiveChief/wireguard-install

## Sanity Checks and automagic
function root-check() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "Sorry, you need to run this as root"
    exit
  fi
}

## Root Check
root-check

## Detect OS
function dist-check() {
  if [ -e /etc/centos-release ]; then
    DISTRO="CentOS"
  elif [ -e /etc/debian_version ]; then
    DISTRO=$( lsb_release -is )
  elif [ -e /etc/arch-release ]; then
    DISTRO="Arch"
  elif [ -e /etc/fedora-release ]; then
    DISTRO="Fedora"
  elif [ -e /etc/redhat-release ]; then
    DISTRO="Redhat"
  else
    echo "Your distribution is not supported (yet)."
    exit
  fi
}

## Check distro
dist-check

function virt-check() {
  ## Deny OpenVZ
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ virtualization is not supported (yet)."
    exit
  fi
  ## Deny LXC
if [ "$(systemd-detect-virt)" == "lxc" ]; then
    echo "LXC virtualization is not supported (yet)."
    exit
  fi
}

## Virtualization Check
virt-check

function detect-ipv4() {
  ## Detect IPV4
if type ping > /dev/null 2>&1; then
    PING="ping -c3 google.com > /dev/null 2>&1"
    else
    PING6="ping -4 -c3 google.com > /dev/null 2>&1"
  fi
if eval "$PING"; then
    IPV4_SUGGESTION="y"
else
    IPV4_SUGGESTION="n"
  fi
}

## Decect IPV4
detect-ipv4

function test-connectivity-v4() {
  ## Test outward facing IPV4
  if [ "$SERVER_HOST_V4" == "" ]; then
    SERVER_HOST_V4="$(wget -qO- -t1 -T2 ipv4.icanhazip.com)"
    if [ "$INTERACTIVE" == "yes" ]; then
      read -rp "System public IPV4 address is $SERVER_HOST_V4. Is that correct? [y/n]: " -e -i "$IPV4_SUGGESTION" CONFIRM
      if [ "$CONFIRM" == "n" ]; then
        echo "Aborted. Use environment variable SERVER_HOST_V4 to set the correct public IP address."
      fi
    fi
  fi
}

## Get IPV4
test-connectivity-v4

function detect-ipv6() {
  ## Detect IPV6
if type ping > /dev/null 2>&1; then
    PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
else
    PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
fi
if eval "$PING6"; then
    IPV6_SUGGESTION="y"
else
    IPV6_SUGGESTION="n"
  fi
}

 ## Decect IPV4
 detect-ipv6

function test-connectivity-v6() {
  ## Test outward facing IPV6
  if [ "$SERVER_HOST_V6" == "" ]; then
    SERVER_HOST_V6="$(wget -qO- -t1 -T2 ipv6.icanhazip.com)"
    if [ "$INTERACTIVE" == "yes" ]; then
      read -rp "System public IPV6 address is $SERVER_HOST_V6. Is that correct? [y/n]: " -e -i "$IPV6_SUGGESTION" CONFIRM
      if [ "$CONFIRM" == "n" ]; then
        echo "Aborted. Use environment variable SERVER_HOST_V6 to set the correct public IP address."
      fi
    fi
  fi
}

  ## Get IPV6
  test-connectivity-v6

## WG Configurator
  WG_CONFIG="/etc/wireguard/wg0.conf"
  if [ ! -f "$WG_CONFIG" ]; then
    INTERACTIVE=${INTERACTIVE:-yes}
    PRIVATE_SUBNET_V4=${PRIVATE_SUBNET_V4:-"10.8.0.1/24"}
    PRIVATE_SUBNET_MASK_V4=$( echo "$PRIVATE_SUBNET_V4" | cut -d "/" -f 2 )
    GATEWAY_ADDRESS_V4="${PRIVATE_SUBNET_V4::-4}1"
    PRIVATE_SUBNET_V6=${PRIVATE_SUBNET_V6:-"fd42:42:42::1/64"}
    PRIVATE_SUBNET_MASK_V6=$( echo "$PRIVATE_SUBNET_V6" | cut -d "/" -f 2 )
    GATEWAY_ADDRESS_V6="${PRIVATE_SUBNET_V6::-4}1"

  ## Determine host port
  function set-port() {
    echo "What port do you want WireGuard server to listen to?"
    echo "   1) 51820 (Recommended)"
    echo "   2) Custom (Advanced)"
    echo "   3) Random [1024-65535]"
    until [[ "$PORT_CHOICE" =~ ^[1-3]$ ]]; do
      read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
    done
    ## Apply port response
    case $PORT_CHOICE in
      1)
      SERVER_PORT="51820"
      ;;
      2)
      until [[ "$SERVER_PORT" =~ ^[0-9]+$ ]] && [ "$SERVER_PORT" -ge 1 ] && [ "$SERVER_PORT" -le 65535 ]; do
        read -rp "Custom port [1-65535]: " -e -i 51820 SERVER_PORT
      done
      ;;
      3)
      SERVER_PORT=$(shuf -i1024-65535 -n1)
      echo "Random Port: $SERVER_PORT"
      ;;
    esac
  }

  ## Set Port
  set-port

  ## What ip version would you like to be available on this VPN?
  function ipvx-select() {
    echo "What IPv do you want to use to connect to WireGuard server?"
    echo "   1) IPv4 (Recommended)"
    echo "   2) IPv6 (Advanced)"
    until [[ "$SERVER_HOST" =~ ^[1-2]$ ]]; do
      read -rp "IP Choice [1-2]: " -e -i 1 SERVER_HOST
    done
    case $SERVER_HOST in
    1)
    SERVER_HOST="$SERVER_HOST_V4"
    ;;
    2)
    SERVER_HOST="[$SERVER_HOST_V6]"
    ;;
    esac
  }

  ## IPv4 or IPv6 Selector
  ipvx-select

  ## Do you want to disable IPv4 or IPv6 or leave them both enabled?
  function disable-ipvx() {
    echo "Do you want to disable IPv4 or IPv6 on the server?"
    echo "   1) No (Recommended)"
    echo "   2) IPV4"
    echo "   3) IPV6"
    until [[ "$DISABLE_HOST" =~ ^[1-3]$ ]]; do
      read -rp "Disable Host Choice [1-3]: " -e -i 1 DISABLE_HOST
    done
    case $DISABLE_HOST in
    1)
    DISABLE_HOST="sysctl --system"
    ;;
    2)
    DISABLE_HOST="$(sysctl -w net.ipv4.conf.all.disable_ipv4=1
    sysctl -w net.ipv4.conf.default.disable_ipv4=1
    sysctl --system)"
    ;;
    3)
    DISABLE_HOST="$(sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    sysctl --system)"
    ;;
    esac
  }

  ## Disable Ipv4 or Ipv6
  disable-ipvx

  ## Would you like to allow connections to your LAN neighbors?
  function client-allowed-ip() {
    echo "What traffic do you want the client to forward to wireguard?"
    echo "   1) Everything (Recommended)"
    echo "   2) Exclude Private IPs (Allows LAN IP connections)"
    until [[ "$CLIENT_ALLOWED_IP" =~ ^[1-2]$ ]]; do
      read -rp "Client Allowed IP Choice [1-2]: " -e -i 1 CLIENT_ALLOWED_IP
    done
    case $CLIENT_ALLOWED_IP in
    1)
    CLIENT_ALLOWED_IP="0.0.0.0/0,::/0"
    ;;
    2)
    CLIENT_ALLOWED_IP="0.0.0.0/1,128.0.0.0/1,::/1,8000::/1"
    ;;
    esac
  }

  ## Traffic Forwarding
  client-allowed-ip

  ## What would you like to name your first WireGuard peer?
  function client-name() {
    echo "Tell me a name for the client config file. Use one word only, no special characters. (No Spaces)"
    read -rp "Client Name: " -e CLIENT_NAME
  }

  ## Client Name
  client-name

  function install-wireguard() {
  ## Installation begins here.
  if [ "$DISTRO" == "Ubuntu" ]; then
    apt-get update
    apt-get install software-properties-common -y
    add-apt-repository ppa:wireguard/wireguard -y
    apt-get update
    apt-get install wireguard qrencode ntpdate linux-headers-"$(uname -r)" haveged iptables-persistent -y
  elif [ "$DISTRO" == "Debian" ]; then
    apt-get update
    echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
    apt-get update
    apt-get install wireguard qrencode ntpdate linux-headers-"$(uname -r)" haveged iptables-persistent -y
  elif [ "$DISTRO" == "Raspbian" ]; then
    apt-get update
    echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
    apt-get install dirmngr -y
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 04EE7237B7D453EC
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
    apt-get update
    apt-get install wireguard qrencode ntpdate raspberrypi-kernel-headers haveged iptables-persistent -y
  elif [ "$DISTRO" == "Arch" ]; then
    pacman -S linux-headers wireguard-dkms wireguard-tools haveged qrencode ntp firewalld
  elif [ "$DISTRO" = 'Fedora' ]; then
    dnf update -y
    dnf copr enable jdoss/wireguard -y
    dnf install qrencode ntpdate kernel-headers-"$(uname -r)" kernel-devel-"$(uname -r)" wireguard-dkms wireguard-tools haveged firewalld -y
  elif [ "$DISTRO" == "CentOS" ]; then
    yum update -y
    wget -O /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
    yum install epel-release -y
    yum install wireguard-dkms wireguard-tools qrencode ntpdate kernel-headers-"$(uname -r)" kernel-devel-"$(uname -r)" haveged firewalld -y
  elif [ "$DISTRO" == "Redhat" ]; then
    yum update -y
    wget -O /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
    yum install epel-release -y
    yum install wireguard-dkms wireguard-tools qrencode ntpdate kernel-headers-"$(uname -r)" kernel-devel-"$(uname -r)" haveged firewalld -y
  fi
}

  ## Install WireGuard
  install-wireguard

  function ip-forwaring() {
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/wireguard.conf
  echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/wireguard.conf
  sysctl --system
}

  ## Ip Forwarding
  ip-forwaring

  function install-firewall() {
  ## Firewall Rules
  if [ "$DISTRO" == "CentOS" ]; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --zone=public --add-port=$SERVER_PORT/udp
    firewall-cmd --zone=trusted --add-source=$PRIVATE_SUBNET_V4
    firewall-cmd --zone=trusted --add-source=$PRIVATE_SUBNET_V6
    firewall-cmd --permanent --zone=public --add-port=$SERVER_PORT/udp
    firewall-cmd --permanent --zone=trusted --add-source=$PRIVATE_SUBNET_V4
    firewall-cmd --permanent --zone=trusted --add-source=$PRIVATE_SUBNET_V6
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V4 ! -d $PRIVATE_SUBNET_V4 -j SNAT --to $SERVER_HOST_V4
    firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V6 ! -d $PRIVATE_SUBNET_V6 -j SNAT --to $SERVER_HOST_V6
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V4 ! -d $PRIVATE_SUBNET_V4 -j SNAT --to $SERVER_HOST_V4
    firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V6 ! -d $PRIVATE_SUBNET_V6 -j SNAT --to $SERVER_HOST_V6
  elif [ "$DISTRO" == "Debian" ]; then
    iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ip6tables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate NEW -s $PRIVATE_SUBNET_V4 -m policy --pol none --dir in -j ACCEPT
    ip6tables -A FORWARD -m conntrack --ctstate NEW -s $PRIVATE_SUBNET_V6 -m policy --pol none --dir in -j ACCEPT
    iptables -t nat -A POSTROUTING -s $PRIVATE_SUBNET_V4 -m policy --pol none --dir out -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -s $PRIVATE_SUBNET_V6 -m policy --pol none --dir out -j MASQUERADE
    iptables -A INPUT -p udp --dport $SERVER_PORT -j ACCEPT
    ip6tables -A INPUT -p udp --dport $SERVER_PORT -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
  elif [ "$DISTRO" == "Ubuntu" ]; then
    iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ip6tables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate NEW -s $PRIVATE_SUBNET_V4 -m policy --pol none --dir in -j ACCEPT
    ip6tables -A FORWARD -m conntrack --ctstate NEW -s $PRIVATE_SUBNET_V6 -m policy --pol none --dir in -j ACCEPT
    iptables -t nat -A POSTROUTING -s $PRIVATE_SUBNET_V4 -m policy --pol none --dir out -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -s $PRIVATE_SUBNET_V6 -m policy --pol none --dir out -j MASQUERADE
    iptables -A INPUT -p udp --dport $SERVER_PORT -j ACCEPT
    ip6tables -A INPUT -p udp --dport $SERVER_PORT -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
  elif [ "$DISTRO" == "Raspbian" ]; then
    iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ip6tables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate NEW -s $PRIVATE_SUBNET_V4 -m policy --pol none --dir in -j ACCEPT
    ip6tables -A FORWARD -m conntrack --ctstate NEW -s $PRIVATE_SUBNET_V6 -m policy --pol none --dir in -j ACCEPT
    iptables -t nat -A POSTROUTING -s $PRIVATE_SUBNET_V4 -m policy --pol none --dir out -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -s $PRIVATE_SUBNET_V6 -m policy --pol none --dir out -j MASQUERADE
    iptables -A INPUT -p udp --dport $SERVER_PORT -j ACCEPT
    ip6tables -A INPUT -p udp --dport $SERVER_PORT -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
  elif [ "$DISTRO" == "Arch" ]; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --zone=public --add-port=$SERVER_PORT/udp
    firewall-cmd --zone=trusted --add-source=$PRIVATE_SUBNET_V4
    firewall-cmd --zone=trusted --add-source=$PRIVATE_SUBNET_V6
    firewall-cmd --permanent --zone=public --add-port=$SERVER_PORT/udp
    firewall-cmd --permanent --zone=trusted --add-source=$PRIVATE_SUBNET_V4
    firewall-cmd --permanent --zone=trusted --add-source=$PRIVATE_SUBNET_V6
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V4 ! -d $PRIVATE_SUBNET_V4 -j SNAT --to $SERVER_HOST_V4
    firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V6 ! -d $PRIVATE_SUBNET_V6 -j SNAT --to $SERVER_HOST_V6
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V4 ! -d $PRIVATE_SUBNET_V4 -j SNAT --to $SERVER_HOST_V4
    firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V6 ! -d $PRIVATE_SUBNET_V6 -j SNAT --to $SERVER_HOST_V6
  elif [ "$DISTRO" == "Fedora" ]; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --zone=public --add-port=$SERVER_PORT/udp
    firewall-cmd --zone=trusted --add-source=$PRIVATE_SUBNET_V4
    firewall-cmd --zone=trusted --add-source=$PRIVATE_SUBNET_V6
    firewall-cmd --permanent --zone=public --add-port=$SERVER_PORT/udp
    firewall-cmd --permanent --zone=trusted --add-source=$PRIVATE_SUBNET_V4
    firewall-cmd --permanent --zone=trusted --add-source=$PRIVATE_SUBNET_V6
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V4 ! -d $PRIVATE_SUBNET_V4 -j SNAT --to $SERVER_HOST_V4
    firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V6 ! -d $PRIVATE_SUBNET_V6 -j SNAT --to $SERVER_HOST_V6
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V4 ! -d $PRIVATE_SUBNET_V4 -j SNAT --to $SERVER_HOST_V4
    firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V6 ! -d $PRIVATE_SUBNET_V6 -j SNAT --to $SERVER_HOST_V6
  elif [ "$DISTRO" == "Redhat" ]; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --zone=public --add-port=$SERVER_PORT/udp
    firewall-cmd --zone=trusted --add-source=$PRIVATE_SUBNET_V4
    firewall-cmd --zone=trusted --add-source=$PRIVATE_SUBNET_V6
    firewall-cmd --permanent --zone=public --add-port=$SERVER_PORT/udp
    firewall-cmd --permanent --zone=trusted --add-source=$PRIVATE_SUBNET_V4
    firewall-cmd --permanent --zone=trusted --add-source=$PRIVATE_SUBNET_V6
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V4 ! -d $PRIVATE_SUBNET_V4 -j SNAT --to $SERVER_HOST_V4
    firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V6 ! -d $PRIVATE_SUBNET_V6 -j SNAT --to $SERVER_HOST_V6
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V4 ! -d $PRIVATE_SUBNET_V4 -j SNAT --to $SERVER_HOST_V4
    firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s $PRIVATE_SUBNET_V6 ! -d $PRIVATE_SUBNET_V6 -j SNAT --to $SERVER_HOST_V6
fi
}

  ## Install Firewall
  install-firewall

  ## WireGuard Set Config
  function wireguard-setconf() {
    SERVER_PRIVKEY=$( wg genkey )
    SERVER_PUBKEY=$( echo "$SERVER_PRIVKEY" | wg pubkey )
    CLIENT_PRIVKEY=$( wg genkey )
    CLIENT_ADDRESS_V4="${PRIVATE_SUBNET_V4::-4}2"
    CLIENT_ADDRESS_V6="${PRIVATE_SUBNET_V6::-4}2"
    PRESHARED_KEY=$( wg genpsk )
    mkdir -p /etc/wireguard
    mkdir -p /etc/wireguard/clients
    touch $WG_CONFIG && chmod 600 $WG_CONFIG
    ## Set Wireguard settings for this host and first peer.

echo "# $PRIVATE_SUBNET_V4 $PRIVATE_SUBNET_V6 $SERVER_HOST:$SERVER_PORT $SERVER_PUBKEY $CLIENT_ALLOWED_IP
[Interface]
Address = $GATEWAY_ADDRESS_V4/$PRIVATE_SUBNET_MASK_V4,$GATEWAY_ADDRESS_V6/$PRIVATE_SUBNET_MASK_V6
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIVKEY
SaveConfig = false
# $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBKEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = $CLIENT_ADDRESS_V4/32,$CLIENT_ADDRESS_V6/128" > $WG_CONFIG

echo "# $CLIENT_NAME
[Interface]
Address = $CLIENT_ADDRESS_V4/$PRIVATE_SUBNET_MASK_V4,$CLIENT_ADDRESS_V6/$PRIVATE_SUBNET_MASK_V6
PrivateKey = $CLIENT_PRIVKEY
[Peer]
AllowedIPs = $CLIENT_ALLOWED_IP
Endpoint = $SERVER_HOST:$SERVER_PORT
PublicKey = $SERVER_PUBKEY" > "/etc/wireguard/clients"/"$CLIENT_NAME"-wg0.conf
qrencode -t ansiutf8 -l L < "/etc/wireguard/clients"/"$CLIENT_NAME"-wg0.conf
echo "Client Config --> "/etc/wireguard/clients"/"$CLIENT_NAME"-wg0.conf"
  ## Restart WireGuard
if pgrep systemd-journal; then
  systemctl restart wg-quick@wg0
else
  service wg-quick@wg0 restart
fi
}
  ## Setting Up Wireguard Config
  wireguard-setconf

  ## Setup Network Time Protocol To Correct Server.
  ntpdate pool.ntp.org

  else

  ## Already installed what next?
  function wireguard-next-questions() {
  echo "Looks like Wireguard is already installed."
  echo "What do you want to do?"
  echo "   1) Uninstall WireGuard"
  echo "   2) Exit"
  until [[ "$WIREGUARD_OPTIONS" =~ ^[1-2]$ ]]; do
    read -rp "Select an Option [1-2]: " -e -i 1 WIREGUARD_OPTIONS
  done
  case $WIREGUARD_OPTIONS in
    1)
    ## Uninstall Wireguard
    read -rp "Do you really want to remove Wireguard? [y/n]:" -e -i n REMOVE_WIREGUARD
  if [ "$DISTRO" == "CentOS" ]; then
    wg-quick down wg0
    yum remove wireguard qrencode ntpdate haveged unbound unbound-host firewalld -y
  elif [ "$DISTRO" == "Debian" ]; then
    wg-quick down wg0
    apt-get remove --purge wireguard qrencode ntpdate haveged unbound unbound-host iptables-persistent -y
    apt-get autoremove -y
  elif [ "$DISTRO" == "Ubuntu" ]; then
    wg-quick down wg0
    apt-get remove --purge wireguard qrencode ntpdate haveged unbound unbound-host iptables-persistent -y
    apt-get autoremove -y
  elif [ "$DISTRO" == "Raspbian" ]; then
    wg-quick down wg0
    apt-get remove --purge wireguard qrencode ntpdate haveged unbound unbound-host dirmngr iptables-persistent -y
    apt-get autoremove -y
  elif [ "$DISTRO" == "Arch" ]; then
    wg-quick down wg0
    pacman -Rs wireguard qrencode ntpdate haveged unbound unbound-host firewalld -y
  elif [ "$DISTRO" == "Fedora" ]; then
    wg-quick down wg0
    dnf remove wireguard qrencode ntpdate haveged unbound unbound-host firewalld -y
  elif [ "$DISTRO" == "Redhat" ]; then
    wg-quick down wg0
    yum remove wireguard qrencode ntpdate haveged unbound unbound-host firewalld -y
  fi
    rm -rf /etc/wireguard
    rm -rf /etc/wireguard/clients
    rm -rf /etc/unbound
    rm -rf /etc/qrencode
    rm /etc/sysctl.d/wireguard.conf
    rm /etc/wireguard/wg0.conf
    rm /etc/unbound/unbound.conf
    rm /etc/ntp.conf
    rm /etc/iptables/rules.v4
    rm /etc/firewalld/firewalld.conf
    rm /etc/default/haveged
    ;;
    2)
    exit
    ;;
  esac
}

## Running Questions Command
wireguard-next-questions

fi
