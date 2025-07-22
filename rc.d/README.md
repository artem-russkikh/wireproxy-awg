# Running wireproxy with rc.d

If you're on a rc.d-based distro, you'll most likely want to run Wireproxy as a systemd unit.

The provided systemd unit assumes you have the wireproxy executable installed on `/bin/wireproxy-awg` and a configuration file stored at `/etc/wireproxy-awg.conf`. These paths can be customized by editing the unit file.

# Setting up the unit

1. Copy the `wireproxy-awg` file from this directory to `/usr/local/etc/rc.d`.

2. If necessary, customize the unit.
   Edit the parts with `procname`, `command`, `wireproxy_conf`  to point to the executable and the configuration file.

4. Add the following lines to `/etc/rc.conf` to enable wireproxy
   `wireproxy_enable="YES"`

5. Start wireproxy service and check status
   ```
   sudo service wireproxy-awg start
   sudo service wireproxy-awg status
   ```
