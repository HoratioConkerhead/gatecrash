# Installing Gatecrash on bare-metal Debian

This is for installing Gatecrash directly on a small machine running Debian
(mini-PC, old laptop, second-hand thin client). For the simpler DietPi
quickstart on a Pi or SBC, see the main [README](../README.md).

This page assumes you've already installed Debian 12 or 13 (netinstall is
fine — same install steps as in [INSTALL-HYPERV.md](INSTALL-HYPERV.md) §3,
just without the VM bits).

You need to be able to SSH into the box (or work directly at its console)
with a user that has `sudo`.

## 1. Confirm networking

```bash
ip addr show
curl -s http://ifconfig.me
```

The first should show a LAN IP on the interface you'll use for ARP
spoofing. The second should return your ISP's IP. If networking isn't
working, fix that before continuing.

## 2. Set the hostname (optional)

If you want the device reachable as `gatecrash.local` on the LAN:

```bash
sudo hostnamectl set-hostname gatecrash
```

(`setup.sh` does this automatically too — skip this step if you're happy
to let setup do it.)

## 3. Clone and run setup

```bash
sudo apt install -y git
git clone https://github.com/HoratioConkerhead/gatecrash
cd gatecrash
sudo bash setup.sh
```

After setup completes, open the web UI at `http://gatecrash.local` and follow
the configuration prompts (WireGuard config, target devices).

---

## Notes on hardware

- **Wired ethernet recommended.** ARP spoofing on a wireless interface is
  unreliable on a lot of consumer chipsets (the wireless driver may rate-limit
  or drop spoofed ARP frames).
- **No MAC-spoofing toggle to worry about** — that's only a concern for
  virtual NICs on Hyper-V or other hypervisors.
