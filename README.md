# Wireguard Install

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

### Wireguard Multi-hop
```
wget https://raw.githubusercontent.com/LiveChief/wireguard-install/master/wireguard-multihop.sh
bash wireguard-multihop.sh
```

Copy $HOME/$CLIENT_NAME-wg0.conf to /etc/wireguard/wg0.conf 

### Setup Wireguard service on client
```
systemctl enable wg-quick@wg0.service
```
### Start Wireguard service on client.
```
systemctl start wg-quick@wg0.service
```
### Stop Wireguard Service
```
systemctl stop wg-quick@wg0.service
```
### Restart Wireguard Service
```
systemctl restart wg-quick@wg0.service
```
### Show Wireguard status
```
wg show
```

