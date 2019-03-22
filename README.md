# wireguard-install

```
curl -O https://raw.githubusercontent.com/LiveChief/wireguard-install/master/wireguard-server.sh
bash wireguard-server.sh
```

Install WireGuard and reboot your computer:
```
apt-get install software-properties-common && add-apt-repository ppa:wireguard/wireguard -y && apt-get update && apt-get install wireguard resolvconf -y
reboot
Copy the file /root/client-wg0.conf from a remote server to your local PC path /etc/wireguard/wg0.conf
systemctl enable wg-quick@wg0.service
systemctl start wg-quick@wg0.service
```

To show VPN status, run 

sudo wg show
