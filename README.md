# keybusdev.ko

A Linux Kernel Module for interacting with the DSC keybus protocol using GPIO
on Linux.

## Features

* exposes a /dev/keybus device for reading all the packets arriving from the
  alarm system
* exposes a kernel object under /sys/keybus for reading the latest state of the
  alarm system and statistics

Tested on:
- Raspberry Pi B (Rev 2.1 UK) using `Linux raspberrypi 4.1.13+ #826 PREEMPT 
Fri Nov 13 20:13:22 GMT 2015 armv6l GNU/Linux`.
- Raspberry Pi 3 Model B Rev 1.2 (Pi 3 B+) using `Linux retropie 4.14.98-v7+ #1200 SMP 
Tue Feb 12 20:27:48 GMT 2019 armv7l GNU/Linux`.

## Installation

Connect keybus DATA to GPIO 23 and keybus CLK to GPIO 24. Remember
that keybus is 12V where as Raspberry PI can only cope with 3.3V. You
need some shield in between. For example, the shield shown below is based 
on configuring the GPIO ports as pull up and then pulling them down to GRDN 
when keybus is high.

![shield.png](shield.png)

### Configure the pins

Use the provided Device Tree file (requires a kernel with Device Tree support)
to configure the GPIO pins to match the way you connected keybus to your device. 

This step is not mandatory if you have a shield that doesn't require a special
setup for the GPIO pins (such as pull up/down). You can also replace this step
by configuring the GPIO some other way (such as using the Linux GPIO subsystem).

To use the provided `dts` file, compile it, install it to your overlays directory
(usually under `/boot`) and reboot.

```
dtc -I dts -O dtb -o keybusdev-overlay.dtb keybusdev-overlay.dts
cp keybusdev-overlay.dtb /boot/overlays
shutdown -r now
```

**For configuring the Device Tree file on Raspberry Pi 3 B+.**

```
dtc -I dts -O dtb -o keybusdev-overlay.dtbo keybusdev-overlay.dts
cp keybusdev-overlay.dtbo /boot/overlays
```


Edit the `/boot/config.txt` file and add/modify `dtoverlay=` line as follows: `dtoverlay=keybusdev-overlay`

```
shutdown -r now
```

### Compile and install the kernel module

```
make
insmod keybusdev.ko 
```

You can use the module parameters `active_low` (default is 0), `gpio_data`
(default 23) and `gpio_clk` (default 24) to specify your configuration.

## The /sys/keybus/ directory

You can use the files under `/sys/keybus` to retrieve statistics and the latest
keybus device status.

For example:

```
cat /sys/keybus/keybus/keybus_status
```

## The /dev/keybus device

The device will internally buffer up to 128 events. If there are more
events coming in before old events are read by user code, then older
events are overwritten.

To read an event, open the `/dev/keybus` device an read. To read the
next event, seek to the beginning of the file and read again. Reading
from offset 0 will block until there is a new event.

You can also use `cat` to retrieve the events.

```
while cat /dev/keybus; do sleep 1; done
```
