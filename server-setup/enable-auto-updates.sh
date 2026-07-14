#!/usr/bin/env bash
# ============================================================
#  Automatische server-updates voor de VPS (Ubuntu/Debian)
#  Zet 'unattended-upgrades' aan: security-updates worden
#  automatisch geinstalleerd, oude pakketten opgeruimd en de
#  server herstart 's nachts als een update dat vereist.
#
#  Eenmalig draaien met sudo:
#    sudo bash server-setup/enable-auto-updates.sh
# ============================================================
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt update
apt install -y unattended-upgrades

# Periodieke taken aanzetten (dagelijks lijst + upgrade, wekelijks opruimen)
tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Lokale voorkeuren als drop-in (laat het hoofdbestand met rust).
# Standaard worden alleen -security updates automatisch geinstalleerd = veilig.
tee /etc/apt/apt.conf.d/52unattended-upgrades-local >/dev/null <<'EOF'
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Automatisch herstarten als een update dat vereist, om 04:00.
// Wil je NOOIT een automatische reboot? Zet Automatic-Reboot op "false".
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF

systemctl enable --now apt-daily.timer apt-daily-upgrade.timer

echo
echo "Klaar. Controleren:"
echo "  systemctl list-timers apt-daily*      # timers actief?"
echo "  sudo unattended-upgrades --dry-run --debug   # testrun"
