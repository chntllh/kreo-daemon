# Kreo Pegasus USB Mapper

Add support for BTN_EXTRA, BTN_SIDE on Linux on wireless 2.4GHz mode.

ID 248a:fa02 Maxxter Wireless Receiver

```bash
mkdir build
cd build

cmake ..
sudo make install
```

```bash
# uinput
echo uinput | sudo tee /etc/modules-load.d/uinput.conf > /dev/null

echo 'KERNEL=="uinput", GROUP="input", MODE="0660", OPTIONS+="static_node=uinput"' | sudo tee /etc/udev/rules.d/99-uinput.rules > /dev/null

echo -e 'SUBSYSTEM=="usb", ATTRS{idVendor}=="248a", ATTRS{idProduct}=="fa02", MODE="0660", GROUP="input"\nKERNEL=="uinput", MODE="0660", GROUP="input"' | sudo tee /etc/udev/rules.d/99-kreo-daemon.rules > /dev/null

# reload udev rules
sudo udevadm control --reload

# user for daemon
sudo useradd -r -M -s /usr/sbin/nologin kreodaemon
```

systemd service

`/usr/lib/systemd/system/kreo-daemon.service`

```bash
[Unit]
Description=Kreo Mouse Daemon
After=network.target
Requires=dev-bus-usb.device

[Service]
Type=simple
ExecStart=/usr/local/bin/kreo-daemon
Restart=on-failure
RestartSec=2
User=kreodaemon
Group=input

[Install]
WantedBy=multi-user.target
```

###### I DONT KNOW WHAT I'M DOING™
