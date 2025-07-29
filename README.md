# Mullvad SOCKS5 Proxy with WireGuard on Linux

A script using [network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) to create a SOCKS5
proxy to a Mullvad VPN server. It does not change your routing table or DNS. This allows you to use e.g. [FoxyProxy](https://getfoxyproxy.org/) 
to selectively enable Mullvad for some websites.

## Installation

On Arch Linux, simply install the AUR package:
```sh
$ yay -S mullvad-socks5-proxy
```

On other distributions, use the following steps after cloning the repository:
```sh
$ sudo cp mullvad-socks5-proxy.sh /usr/bin/mullvad-socks5-proxy
$ sudo chmod +x /usr/bin/mullvad-socks5-proxy
$ sudo cp mullvad-socks5-proxy.service /usr/lib/systemd/system/
```

## Configuration

1. Go to the [Wireguard configuration page](https://mullvad.net/en/account/wireguard-config) on your Mullvad account and 
download the configuration files for the servers you want.
2. Extract the ZIP archive to `/etc/mullvad-socks5-proxy`. Each file will be named `<server-name>.conf`.
3. Start the proxy with `systemctl start mullvad-socks5-proxy@<server-name>.service`
4. Verify the proxy connection with curl. You should see a Mullvad IP:
```sh
$ curl --socks5-hostname 127.0.0.1:1080 https://am.i.mullvad.net
```
5. To use a different port, add the following to `/etc/mullvad-socks5-proxy/<server-name>.conf`:
```ini
[Custom]
SOCKS5Port = 1234
```