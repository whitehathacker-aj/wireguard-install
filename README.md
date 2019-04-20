# wireguard-install

### Wireguard Server
```
wget https://raw.githubusercontent.com/LiveChief/wireguard-install/master/wireguard-server.sh
bash wireguard-server.sh
```

### Wireguard Client
```
wget https://raw.githubusercontent.com/LiveChief/wireguard-install/master/wireguard-client.sh
bash wireguard-client.sh
```

Copy /root/client-wg0.conf to /etc/wireguard/wg0.conf

### Setup Wireguard service on client
```
systemctl enable wg-quick@wg0.service
systemctl start wg-quick@wg0.service
```

### Show Wireguard status
```
wg show
```
