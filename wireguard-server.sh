#!/bin/bash
# Secure WireGuard For CentOS, Debian, Ubuntu, Arch, Fedora, Redhat, Raspbian
# https://github.com/LiveChief/wireguard-install
#

WG_CONFIG="/etc/wireguard/wg0.conf"

if [[ "$EUID" -ne 0 ]]; then
    echo "Sorry, you need to run this as root"
    exit
fi

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
    echo "Your distribution is not supported (yet)"
    exit
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ virtualization is not supported."
    exit
fi

if [ "$(systemd-detect-virt)" == "lxc" ]; then
    echo "LXC virtualization is not supported."
    exit
fi

if [ ! -f "$WG_CONFIG" ]; then
    ### Install server and add default client
    INTERACTIVE=${INTERACTIVE:-yes}
    PRIVATE_SUBNET_V4=${PRIVATE_SUBNET_V4:-"10.8.0.0/24"}
    PRIVATE_SUBNET_MASK_V4=$( echo $PRIVATE_SUBNET_V4 | cut -d "/" -f 2 )
    GATEWAY_ADDRESS_V4="${PRIVATE_SUBNET_V4::-4}1"
    PRIVATE_SUBNET_V6=${PRIVATE_SUBNET_V6:-"fd42:42:42::0/64"}
    PRIVATE_SUBNET_MASK_V6=$( echo $PRIVATE_SUBNET_V6 | cut -d "/" -f 2 )
    GATEWAY_ADDRESS_V6="${PRIVATE_SUBNET_V6::-4}1"

    if [ "$SERVER_HOST_V4" == "" ]; then
        SERVER_HOST_V4="$(wget -qO- -t1 -T2 ipv4.icanhazip.com)"
        if [ "$INTERACTIVE" == "yes" ]; then
            read -p "Servers public IPV4 address is $SERVER_HOST_V4. Is that correct? [y/n]: " -e -i "y" CONFIRM
            if [ "$CONFIRM" == "n" ]; then
                echo "Aborted. Use environment variable SERVER_HOST_V4 to set the correct public IP address"
                exit
            fi
        fi
    fi

if [ "$SERVER_HOST_V6" == "" ]; then
        SERVER_HOST_V6="$(wget -qO- -t1 -T2 ipv6.icanhazip.com)"
        if [ "$INTERACTIVE" == "yes" ]; then
            read -p "Servers public IPV6 address is $SERVER_HOST_V6. Is that correct? [y/n]: " -e -i "y" CONFIRM
            if [ "$CONFIRM" == "n" ]; then
                echo "Aborted. Use environment variable SERVER_HOST_V6 to set the correct public IP address"
                exit
            fi
        fi
    fi

    	echo "What port do you want WireGuard to listen to?"
	echo "   1) Automatic (Recommended)"
	echo "   2) Custom"
	echo "   3) Random [2000-65535]"
	until [[ "$PORT_CHOICE" =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
	done
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
			# Generate random number within private ports range
			SERVER_PORT=$(shuf -i2000-65535 -n1)
			echo "Random Port: $SERVER_PORT"
		;;
	esac

    echo "Do you want to turn on Persistent Keepalive?"
    echo "   1) Automatic (Recommended)"
    echo "   2) Custom"
    until [[ "$NAT_CHOICE" =~ ^[1-2]$ ]]; do
        read -rp "Nat Choice [1-2]: " -e -i 1 NAT_CHOICE
    done
    case $NAT_CHOICE in
        1)
			NAT_CHOICE="25"
        ;;
	2)
			until [[ "$NAT_CHOICE " =~ ^[0-9]+$ ]] && [ "$NAT_CHOICE " -ge 1 ] && [ "$NAT_CHOICE " -le 25]; do
				read -rp "Custom NAT [0-25]: " -e -i 25 NAT_CHOICE 
			done
		;;
    esac

	echo "What MTU do you want to use?"
	echo "   1) Automatic (Recommended)"
	echo "   2) Custom"
	until [[ "$MTU_CHOICE" =~ ^[1-2]$ ]]; do
		read -rp "MTU choice [1-2]: " -e -i 1 MTU_CHOICE
	done
	case $MTU_CHOICE in
		1)
			MTU_CHOICE="1280"
		;;
		2)
			until [[ "$MTU_CHOICE" =~ ^[0-9]+$ ]] && [ "$MTU_CHOICE" -ge 1 ] && [ "$MTU_CHOICE" -le 1500 ]; do
				read -rp "Custom MTU [0-1500]: " -e -i 1500 MTU_CHOICE
			done
		;;
	esac

    echo "What IPv do you want to use to connect to WireGuard server?"
    echo "   1) Automatic (Recommended)"
    echo "   2) IPv6"
    until [[ "$SERVER_HOST" =~ ^[1-2]$ ]]; do
        read -rp "IP Choice [1-2]: " -e -i 1 SERVER_HOST
    done
    case $SERVER_HOST in
        1)
            SERVER_HOST="$SERVER_HOST_V4"
        ;;
        3)
            SERVER_HOST="[$SERVER_HOST_V6]"
        ;;
    esac

    echo "Do you want to disable IPv on the server?"
    echo "   1) Automatic (Recommended)"
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

    echo "What traffic do you want the client to forward to wireguard?"
    echo "   1) Automatic (Recommended)"
    echo "   2) Exclude Private IPs"
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

    read -rp "Do You Want To Install Unbound (y/n) " -e -i y INSTALL_UNBOUND

    if [ "$INSTALL_UNBOUND" == "n" ]; then
        echo "Which DNS do you want to use with the VPN?"
        echo "   1) AdGuard (Recommended)"
        echo "   2) Google"
        echo "   3) OpenDNS"
        echo "   4) Cloudflare"
        echo "   5) Verisign"
        echo "   6) Quad9"
        echo "   7) FDN"
        echo "   8) DNS.WATCH"
        echo "   9) Yandex Basic"
        echo "   10) Clean Browsing"
        read -p "DNS [1-10]: " -e -i 1 DNS_CHOICE

        case $DNS_CHOICE in
            1)
	    CLIENT_DNS="176.103.130.130,176.103.130.131,2a00:5a60::ad1:0ff,2a00:5a60::ad2:0ff"
            ;;
            2)
            CLIENT_DNS="8.8.8.8,8.8.4.4,2001:4860:4860::8888,2001:4860:4860::8844"
            ;;
            3)
            CLIENT_DNS="208.67.222.222,208.67.220.220,2620:119:35::35,2620:119:53::53"
            ;;
            4)
            CLIENT_DNS="1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"
            ;;
            5)
            CLIENT_DNS="64.6.64.6,64.6.65.6,2620:74:1b::1:1,2620:74:1c::2:2"
            ;;
            6)
            CLIENT_DNS="9.9.9.9,149.112.112.112,2620:fe::fe,2620:fe::9"
            ;;
            7)
            CLIENT_DNS="80.67.169.40,80.67.169.12,2001:910:800::40,2001:910:800::12"
            ;;
            8)
            CLIENT_DNS="84.200.69.80,84.200.70.40,2001:1608:10:25::1c04:b12f,2001:1608:10:25::9249:d69b"
            ;;
            9)
            CLIENT_DNS="77.88.8.8,77.88.8.1,2a02:6b8::feed:0ff,2a02:6b8:0:1::feed:0ff"
            ;;
            10)
            CLIENT_DNS="185.228.168.9,185.228.169.9,2a0d:2a00:1::2,2a0d:2a00:2::2"
            ;;
        esac

    fi

    if [ "$DISTRO" == "Ubuntu" ]; then
	apt-get update
	apt-get install software-properties-common -y
	add-apt-repository ppa:wireguard/wireguard -y
	apt-get update
	apt-get install wireguard qrencode ntpdate linux-headers-$(uname -r) haveged -y
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
	$DISABLE_HOST

    elif [ "$DISTRO" == "Debian" ]; then
	apt-get update
	echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
	printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
	apt-get update
        apt-get install wireguard qrencode ntpdate linux-headers-$(uname -r) haveged -y
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
	$DISABLE_HOST

    elif [ "$DISTRO" == "Arch" ]; then
	pacman -S linux-headers wireguard-dkms wireguard-tools haveged qrencode ntp
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
	$DISABLE_HOST

    elif [ "$DISTRO" = 'Fedora' ]; then
	dnf update -y
	dnf copr enable jdoss/wireguard -y
	dnf install qrencode ntpdate kernel-headers-$(uname -r) kernel-devel-$(uname -r) wireguard-dkms wireguard-tools haveged -y
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
	$DISABLE_HOST
	
    elif [ "$DISTRO" == "CentOS" ]; then
	yum update -y
	wget -O /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
	yum install epel-release wireguard-dkms wireguard-tools qrencode ntpdate kernel-headers-$(uname -r) kernel-devel-$(uname -r) haveged -y
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
	$DISABLE_HOST

    elif [ "$DISTRO" == "Redhat" ]; then
	yum update -y
	wget -O /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
	yum install epel-release wireguard-dkms wireguard-tools qrencode ntpdate kernel-headers-$(uname -r) kernel-devel-$(uname -r) haveged -y
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
	$DISABLE_HOST

    fi

    if [[ $INSTALL_UNBOUND = 'y' ]]; then
    apt-get install unbound unbound-host e2fsprogs -y
    wget -O /etc/unbound/root.hints https://www.internic.net/domain/named.cache
    echo "" > /etc/unbound/unbound.conf
  echo "server:
  num-threads: 4
  do-ip4: yes
  do-ip6: yes
  do-udp: yes
  verbosity: 1
  root-hints: "/etc/unbound/root.hints"
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
  interface: 0.0.0.0
  interface: ::0
  max-udp-size: 3072
  access-control: 0.0.0.0/0                 refuse
  access-control: 127.0.0.1                 allow
  access-control: 10.8.0.0/24               allow
  private-address: 10.8.0.0/24
  hide-identity: yes
  hide-version: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  harden-referral-path: yes
  unwanted-reply-threshold: 10000000
  val-log-level: 1
  cache-min-ttl: 1800
  cache-max-ttl: 14400
  prefetch: yes
  qname-minimisation: yes
  prefetch-key: yes" > /etc/unbound/unbound.conf
chown -R unbound:unbound /var/lib/unbound
systemctl enable unbound
service unbound restart
chattr -i /etc/resolv.conf
sed -i "s|nameserver|#nameserver|" /etc/resolv.conf
sed -i "s|search|#search|" /etc/resolv.conf
echo "nameserver 127.0.0.1" >> /etc/resolv.conf
chattr +i /etc/resolv.conf
iptables -A INPUT -s 10.8.0.0/24 -p udp -m udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
CLIENT_DNS="10.8.0.1"	
fi

    SERVER_PRIVKEY=$( wg genkey )
    SERVER_PUBKEY=$( echo $SERVER_PRIVKEY | wg pubkey )
    CLIENT_PRIVKEY=$( wg genkey )
    CLIENT_PUBKEY=$( echo $CLIENT_PRIVKEY | wg pubkey )
    CLIENT_ADDRESS_V4="${PRIVATE_SUBNET_V4::-4}3"
    CLIENT_ADDRESS_V6="${PRIVATE_SUBNET_V6::-4}3"
    PRESHARED_KEY=$( wg genpsk )

    mkdir -p /etc/wireguard
    touch $WG_CONFIG && chmod 600 $WG_CONFIG

    echo "# $PRIVATE_SUBNET_V4 $PRIVATE_SUBNET_V6 $SERVER_HOST:$SERVER_PORT $SERVER_PUBKEY $CLIENT_DNS $MTU_CHOICE $NAT_CHOICE $CLIENT_ALLOWED_IP
[Interface]
Address = $GATEWAY_ADDRESS_V4/$PRIVATE_SUBNET_MASK_V4,$GATEWAY_ADDRESS_V6/$PRIVATE_SUBNET_MASK_V6
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIVKEY
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
SaveConfig = false" > $WG_CONFIG

    echo "# client
[Peer]
PublicKey = $CLIENT_PUBKEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = $CLIENT_ADDRESS_V4/32,$CLIENT_ADDRESS_V6/128" >> $WG_CONFIG

    echo "[Interface]
PrivateKey = $CLIENT_PRIVKEY
Address = $CLIENT_ADDRESS_V4/$PRIVATE_SUBNET_MASK_V4,$CLIENT_ADDRESS_V6/$PRIVATE_SUBNET_MASK_V6
DNS = $CLIENT_DNS
MTU = $MTU_CHOICE
[Peer]
PublicKey = $SERVER_PUBKEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = $CLIENT_ALLOWED_IP
Endpoint = $SERVER_HOST:$SERVER_PORT
PersistentKeepalive = $NAT_CHOICE" > $HOME/client-wg0.conf
qrencode -t ansiutf8 -l L < $HOME/client-wg0.conf

    systemctl enable wg-quick@wg0.service
    systemctl start wg-quick@wg0.service
    ntpdate pool.ntp.org

    echo "Client config --> $HOME/client-wg0.conf"
    echo "Now reboot the server and enjoy your fresh VPN installation! :^)"

else
    ### Server is installed, add a new client
    CLIENT_NAME="$1"
    if [ "$CLIENT_NAME" == "" ]; then
        echo "Tell me a name for the client config file. Use one word only, no special characters."
        read -p "Client name: " -e CLIENT_NAME
    fi
    CLIENT_PRIVKEY=$( wg genkey )
    CLIENT_PUBKEY=$( echo $CLIENT_PRIVKEY | wg pubkey )
    PRESHARED_KEY=$( wg genpsk )
    PRIVATE_SUBNET_V4=$( head -n1 $WG_CONFIG | awk '{print $2}')
    PRIVATE_SUBNET_MASK_V4=$( echo $PRIVATE_SUBNET_V4 | cut -d "/" -f 2 )
    PRIVATE_SUBNET_V6=$( head -n1 $WG_CONFIG | awk '{print $3}')
    PRIVATE_SUBNET_MASK_V6=$( echo $PRIVATE_SUBNET_V6 | cut -d "/" -f 2 )
    SERVER_ENDPOINT=$( head -n1 $WG_CONFIG | awk '{print $4}')
    SERVER_PUBKEY=$( head -n1 $WG_CONFIG | awk '{print $5}')
    CLIENT_DNS=$( head -n1 $WG_CONFIG | awk '{print $6}')
    MTU_CHOICE=$( head -n1 $WG_CONFIG | awk '{print $7}')
    NAT_CHOICE=$( head -n1 $WG_CONFIG | awk '{print $8}')
    CLIENT_ALLOWED_IP=$( head -n1 $WG_CONFIG | awk '{print $9}')
    LASTIP4=$( grep "/32" $WG_CONFIG | tail -n1 | awk '{print $3}' | cut -d "/" -f 1 | cut -d "." -f 4 )
    LASTIP6=$( grep "/128" $WG_CONFIG | tail -n1 | awk '{print $6}' | cut -d "/" -f 1 | cut -d "." -f 4 )
    CLIENT_ADDRESS_V4="${PRIVATE_SUBNET_V4::-4}$((LASTIP4+1))"
    CLIENT_ADDRESS_V6="${PRIVATE_SUBNET_V6::-4}$((LASTIP4+1))"
    echo "# $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBKEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = $CLIENT_ADDRESS_V4/32,$CLIENT_ADDRESS_V6/128" >> $WG_CONFIG

    echo "[Interface]
PrivateKey = $CLIENT_PRIVKEY
Address = $CLIENT_ADDRESS_V4/$PRIVATE_SUBNET_MASK_V4,$CLIENT_ADDRESS_V6/$PRIVATE_SUBNET_MASK_V6
DNS = $CLIENT_DNS
MTU = $MTU_CHOICE
[Peer]
PublicKey = $SERVER_PUBKEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = $CLIENT_ALLOWED_IP
Endpoint = $SERVER_ENDPOINT
PersistentKeepalive = $NAT_CHOICE" > $HOME/$CLIENT_NAME-wg0.conf
qrencode -t ansiutf8 -l L < $HOME/$CLIENT_NAME-wg0.conf

    systemctl restart wg-quick@wg0.service
    echo "New client added, new configuration file for the client on  --> $HOME/$CLIENT_NAME-wg0.conf"
fi
