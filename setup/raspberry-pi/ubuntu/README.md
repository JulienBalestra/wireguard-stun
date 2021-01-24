# Install raspberry pi 4 ubuntu 20.04


https://ubuntu.com/download/raspberry-pi

Prepare the image
```bash
curl -LO https://cdimage.ubuntu.com/releases/20.04.1/release/ubuntu-20.04.1-preinstalled-server-arm64+raspi.img.xz 
xz -d ubuntu-20.04.1-preinstalled-server-arm64+raspi.img.xz
sudo balena-etcher

# installation through the graphic interface

sudo mount "/dev/${device}2" /mnt
sudo touch ssh /mnt
```

```bash
mkdir -pv /home/ubuntu/.ssh
cat << EOF | sudo tee /home/ubuntu/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCoOkvr8GiBsjmD72ueXMTK9b0Kf1+/uzo7gxgr/fgoTAUfWYtvLeoPpGZPB07ha/5wRjDTOWxim18IW2cAVxyekCzkE2NferVj9tY9L0ZB0Q2EFlBXfQ8W5y73r8uO52HS/hWpeVCopvBk8w2QQbovn4D9bMPqtIKaJEXtSw661vnQqu09v7p4cPa62zdEeZP31LOGy4Gxj3jcgkvpNkuzELXvXmfWunjNaOGl5wEpqfgau1T7gUdAn57E+0nWB0zzG7cT3KFrXze8SLc7aDDtlJyF2KdC/4WHAOWHXLD8u3UYriaE7cRuLiiFXWFk8oK6MvqhSLNu/2FBd+5898rgue8Eu/5OJ/6YcK4Kz2z2ricwzIFwTmnsUcJQGLYtj5IkFmfpYUT5O58hniXa+N9D4qvAyVcN/reAo+fTgNNe4EVI+KNh5umx5I0BASefSXSXcIHsvzZceUD+M/WnxmsP28fwscpF6mlCubCrvoz1jsS49OaAlJUQPy+gNJGW1jjzFzyutI/2T68AjcGdicUKUOUvMtRRwFhzmzxycZ72/XGR1ZchZzIJ251dnAR2JBiVhPZrCyfPoV50/UEhV4L3CcRxdiIEb5UBitp9VbEdz8/IP5cxDKIhM8O6L8Vk3leQMkc+PHrunjrcpKOeIQXNkFl6omG3aIAQhTeR4SPh8w== /home/jb/.ssh/id_rsa
EOF
```

Wireguard installation:
```bash
sudo apt-get update && sudo apt-get upgrade -y

cat << EOF | sudo tee /etc/sysctl.d/wireguard.conf
net.ipv4.ip_forward=1
net.ipv4.tcp_congestion_control=bbr
EOF

sudo reboot
sudo apt-get install -y wireguard vim curl iperf iperf3
```

Disable services
```bash
sudo apt-get remove snapd apparmor cloud-init isc-dhcp-client isc-dhcp-common rsyslog ubuntu-minimal
sudo apt-get autoremove
sudo apt-get autopurge
sudo systemctl daemon-reload
sudo rm -Rf /var/cache/snapd /etc/network /etc/dhcp

sudo systemctl disable apt-daily.timer
sudo systemctl mask apt-daily.timer
sudo systemctl disable apt-daily.service
sudo systemctl mask apt-daily.service

sudo systemctl disable apt-daily-upgrade.timer
sudo systemctl mask apt-daily-upgrade.timer
sudo systemctl disable apt-daily-upgrade.service
sudo systemctl mask apt-daily-upgrade.service

sudo systemctl disable man-db.service
sudo systemctl disable man-db.timer
sudo systemctl mask man-db.timer
```

tmpfs and overlay:
```bash
sudo mkdir -pv /etc/systemd/journald.conf.d/
cat << EOF | sudo tee /etc/systemd/journald.conf.d/storage.conf
[Journal]
Storage=volatile
EOF

# TODO: set according available memory
SIZE=1024M
cat << EOF | sudo tee /usr/local/bin/overlay
#!/bin/bash

mkdir -pv /mnt/var-overlay
mount -t tmpfs -o size=${SIZE} tmpfs /mnt/var-overlay
mkdir -pv /mnt/var-overlay/{upper,work}
mount -t overlay overlay -olowerdir=/var,upperdir=/mnt/var-overlay/upper,workdir=/mnt/var-overlay/work /var
EOF
sudo chmod +x /usr/local/bin/overlay


cat << EOF | sudo tee /etc/systemd/system/overlay.service
[Unit]
Before=local-fs.target
Wants=local-fs.target

[Service]
ExecStart=/usr/local/bin/overlay
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable overlay.service
sudo rm -Rf /var/log
sudo mkdir -pv /var/log
sudo systemctl start overlay.service
```

Translate `eth0` mac as hostname:
```bash
ip link show eth0 | grep ether | awk '{print $2}' | tr : - | sudo tee /etc/hostname
cat << EOF | sudo tee /etc/hosts
127.0.0.1 localhost $(cat /etc/hostname)
EOF
```

Disable systemd resolved
```bash
sudo systemctl disable systemd-resolved.service
sudo systemctl mask systemd-resolved.service
sudo rm -v /etc/resolv.conf

cat << EOF | sudo tee /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
EOF
```

Setup wireless access point bridged to ethernet:
```bash
sudo mv -v /lib/systemd/network/80-wifi-adhoc.network /lib/systemd/network/80-wifi-adhoc.network.bak

cat << EOF | sudo tee /etc/systemd/network/00-br0.netdev
[NetDev]
Name=br0
Kind=bridge
EOF

cat << EOF | sudo tee /etc/systemd/network/01-eth0-br0.network
[Match]
Name=eth0

[Network]
Bridge=br0
EOF

cat << EOF | sudo tee /etc/systemd/network/br0.network
[Match]
Name=br0

[Network]
MulticastDNS=yes
DHCP=yes
EOF

sudo systemctl enable systemd-networkd.service
sudo systemctl restart systemd-networkd.service

sudo mkdir -pv "/etc/systemd/system/wpa_supplicant@wlan0.service.d"
cat << EOF | sudo tee /etc/systemd/system/wpa_supplicant@wlan0.service.d/override.conf
[Service]
ExecStartPre=/sbin/iw dev %i set type __ap
ExecStartPre=/bin/ip link set %i master br0

ExecStart=
ExecStart=/sbin/wpa_supplicant -c/etc/wpa_supplicant/wpa_supplicant-%I.conf -Dnl80211,wext -i%I -bbr0

ExecStopPost=-/bin/ip link set %i nomaster
ExecStopPost=-/sbin/iw dev %i set type managed
EOF

# TODO: set ssid and psk
cat << EOF | sudo tee /etc/wpa_supplicant/wpa_supplicant-wlan0.conf
country=US
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="rpi"
    mode=2
    frequency=2437
    key_mgmt=WPA-PSK
    proto=RSN WPA
    psk="12345678"
}
EOF
sudo chmod 600 /etc/wpa_supplicant/wpa_supplicant-wlan0.conf

sudo systemctl daemon-reload
sudo systemctl enable wpa_supplicant@wlan0.service
sudo systemctl restart wpa_supplicant@wlan0.service
```

In case there is a wireguard PostUp PostDown with the interface `eth0`, replace by `br0`:
```
PostUp =   iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o br0 -j MASQUERADE

PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o br0 -j MASQUERADE
```

Cleaning:
```bash
sudo apt-get autoclean && sudo apt-get autoremove -y
```
