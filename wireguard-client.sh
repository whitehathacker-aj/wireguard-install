#!/bin/bash
#
# https://github.com/LiveChief/wireguard-install
#

if [[ "$EUID" -ne 0 ]]; then
    echo "Sorry, you need to run this as root"
    exit
fi

if [ -e /etc/centos-release ]; then
    DISTRO="CentOS"
elif [ -e /etc/debian_version ]; then
    DISTRO=$( lsb_release -is )
elif [[ -e /etc/arch-release ]]; then
    DISTRO="Arch"
elif [[ -e /etc/fedora-release ]]; then
    DISTRO="Fedora"
else
    echo "Your distribution is not supported (yet)"
    exit
fi

    if [ "$DISTRO" == "Ubuntu" ]; then
    apt-get update
	apt-get upgrade -y
	apt-get dist-upgrade -y
	apt-get install software-properties-common -y
    add-apt-repository ppa:wireguard/wireguard -y
    apt-get update
    apt-get install wireguard qrencode unattended-upgrades apt-listchanges build-essential haveged ntpdate linux-headers-$(uname -r) -y
    wget -q -O /etc/apt/apt.conf.d/50unattended-upgrades "https://raw.githubusercontent.com/LiveChief/unattended-upgrades/master/ubuntu/50unattended-upgrades.Ubuntu"
	ntpdate pool.ntp.org
	apt-get clean -y
	apt-get autoremove -y
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
	$DISABLE_HOST
	
    elif [ "$DISTRO" == "Debian" ]; then
    echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
    apt-get update
	apt-get upgrade -y
	apt-get dist-upgrade -y
    apt-get install wireguard qrencode unattended-upgrades apt-listchanges build-essential haveged ntpdate linux-headers-$(uname -r) -y
    wget -q -O /etc/apt/apt.conf.d/50unattended-upgrades "https://raw.githubusercontent.com/LiveChief/unattended-upgrades/master/debian/50unattended-upgrades.Debian"
	ntpdate pool.ntp.org
	apt-get clean -y
	apt-get autoremove -y
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
	$DISABLE_HOST
	
    elif [ "$DISTRO" == "Arch" ]; then
	pacman -Syy
	pacman -S wireguard-tools

    elif [[ "$DISTRO" = 'Fedora' ]]; then
	dnf update -y
	dnf upgrade -y
	dnf copr enable jdoss/wireguard -y
	dnf install wireguard-dkms wireguard-tools qrencode firewalld ntpdate kernel-devel kernel-headers -y
	ntpdate pool.ntp.org

    elif [ "$DISTRO" == "CentOS" ]; then
	yum update -y
    wget -O /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
    yum install epel-release -y
    yum install wireguard-dkms qrencode wireguard-tools ntpdate firewalld linux-headers-$(uname -r) -y
    yum clean all -y
    ntpdate pool.ntp.org
    
    fi
