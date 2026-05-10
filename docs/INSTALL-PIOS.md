# Installing Gatecrash on Raspberry Pi OS Lite

This is the step-by-step install path for **Raspberry Pi OS Lite** (the
command-line-only Pi OS). For the simpler DietPi quickstart, see the
main [README](../README.md). For other platforms, see
[INSTALL-HYPERV.md](INSTALL-HYPERV.md) or [INSTALL-DEBIAN.md](INSTALL-DEBIAN.md).

> You don't need a monitor, keyboard, or mouse — the Raspberry Pi Imager sets up
> all the remote access for you. You may want to plug into a monitor if there
> are issues.

This should work on a 4 GB card but hasn't been tested at that size.

## 1. Prepare the SD card

On a computer, install [Raspberry Pi Imager](https://www.raspberrypi.com/software/)
and configure the OS:

1. Pick OS → **Raspberry Pi OS (other)** → **Raspberry Pi OS Lite (64-bit)**
2. Set hostname to `gatecrash`
3. Create a username and password
4. Enable SSH (password or public key — password is easiest)
5. Optionally enable Raspberry Pi Connect (not required)

## 2. Boot and log in

1. Insert the SD card into the Pi
2. Plug into ethernet
3. Turn on — first boot takes a few minutes to set up
4. SSH in from another computer:
   ```
   ssh gatecrash -l <your-username>
   ```
   Accept the fingerprint, enter your password.

## 3. Install Gatecrash

This installs dependencies, clones the repo, and runs the setup script. It
starts the web UI but does not start Gatecrash itself.

```bash
sudo apt install -y git
git clone https://github.com/HoratioConkerhead/gatecrash
cd gatecrash
sudo bash setup.sh
```

## 4. Open the web UI

On a computer or mobile device, visit:

```
http://gatecrash.local
```

Follow the prompts to set a password (or skip for no-auth) and choose HTTPS.
Then configure your WireGuard config and target devices.

## 5. Test WireGuard

Use the **Start WireGuard** and **Check VPN IP** buttons in the web UI before
starting Gatecrash itself.

## 6. Start Gatecrash

Use the **Start Gatecrash** button in the web UI.

---

## CLI commands (if preferred)

```bash
sudo /opt/gatecrash/start.sh           # start Gatecrash
sudo /opt/gatecrash/stop.sh            # stop and restore normal routing
sudo systemctl status gatecrash        # Gatecrash service status
sudo systemctl status gatecrash-webui  # web UI status
```
