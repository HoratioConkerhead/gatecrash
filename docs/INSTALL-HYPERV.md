# Installing Gatecrash in a Hyper-V VM

This sets up a Debian 13 VM on Hyper-V that acts as the Gatecrash appliance.
For the simpler DietPi quickstart on a Pi or SBC, see the main
[README](../README.md).

> **Note:** The Hyper-V flow is more involved than it needs to be. For most
> users, a Pi or SBC running DietPi is the path of least resistance. This
> file is here for people who already run their LAN tooling in Hyper-V and
> would rather add another VM than another box.

## 1. Create an External Virtual Switch

The VM needs to appear directly on your physical LAN, not on an isolated
virtual network.

1. Open **Hyper-V Manager**
2. **Action → Virtual Switch Manager**
3. Select **External** → **Create Virtual Switch**
4. Name it (e.g. `LAN Bridge`)
5. Under **Connection type**, select **External network** and choose your
   physical NIC from the dropdown
6. Leave **Allow management OS to share this network adapter** checked
   (this keeps your Windows host connected to the LAN through the same NIC)
7. Click **OK**

## 2. Create the VM

In **Hyper-V Manager**:

- **New → Virtual Machine**
- Generation 2 (UEFI), 1–2 vCPUs, 1–2 GB RAM
- Disk: 8 GB
- Network: select the **External Virtual Switch** you just created
- ISO: **Debian 13 netinstall** — the small installation image from
  [debian.org](https://www.debian.org/distrib/)

Then before starting, go into **Settings**:

- **Security** → disable Secure Boot
- **Network Adapter → Advanced Features**:
  - Enable **MAC address spoofing** (required — without this, ARP spoof
    packets are silently dropped and nothing will work)
  - Optionally switch MAC address from **Dynamic** to **Static** and note
    the value (e.g. `52-54-00-AB-CD-EF` — the `52-54-00` prefix is
    conventionally used for VMs). You can use this for a DHCP reservation
    on your router.

## 3. Install Debian

Start the VM and connect to it. Choose **graphical install** or plain
**install** — either works.

- Language: English, location: UK, locale: British English
- Hostname: `gatecrash`, domain: leave blank
- Set a root password (keep a note of it)
- Create a user account with a username and password of your choice
- Disk: **Guided — use entire disk**, partitioning scheme:
  **all files in one partition**
- Extra media: No
- Mirror: pick any

**Software selection** — uncheck everything except:

- **SSH server**
- **Standard system utilities**

No desktop environment.

## 4. Post-install: enable sudo

Log in as your user. You'll need `su` to run root commands until `sudo` is
set up:

```bash
su -
/usr/sbin/usermod -aG sudo yourusername
exit
```

Log out and back in, then verify:

```bash
sudo apt update
```

## 5. Enable SSH password authentication

```bash
sudo nano /etc/ssh/sshd_config
```

Make sure these lines are set to `yes`:

```
PasswordAuthentication yes
KbdInteractiveAuthentication yes
```

Then:

```bash
sudo systemctl restart ssh
```

You can now SSH in from Windows: `ssh yourusername@192.168.1.x`

## 6. Confirm networking

Verify the VM got the expected IP and can reach the internet:

```bash
ip addr show
curl -s http://ifconfig.me
```

That should return your ISP's IP. If networking isn't working, check the
virtual switch assignment.

## 7. Clone and run setup

```bash
sudo apt install -y git
git clone https://github.com/HoratioConkerhead/gatecrash
cd gatecrash
sudo bash setup.sh
```

After setup completes, open the web UI at `http://gatecrash.local` and follow
the configuration prompts (WireGuard config, target devices).
