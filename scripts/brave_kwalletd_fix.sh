#!/usr/bin/env sh
# Fix the "Brave password manager is empty though Login Data has rows" trap.
#
# Cause: the browser hides saved passwords it cannot decrypt (no keyring).
# Under GNOME the KDE keyring (kwalletd6) is often not running, so Brave's
# os-crypt has no key. This script starts kwalletd6 and installs an
# autostart entry so it survives reboots on non-Plasma desktops.
#
# Usage: ./brave_kwalletd_fix.sh   (then FULLY restart the browser!)

set -eu

echo "==> wallet state:"
ls -la ~/.local/share/kwalletd/ 2>/dev/null || echo "    (no wallet dir yet — will be created on first use)"

# 1. start the service right now (idempotent)
if systemctl --user is-active --quiet kwalletd6.service 2>/dev/null; then
    echo "==> kwalletd6 already running"
else
    echo "==> starting kwalletd6"
    systemctl --user start kwalletd6.service 2>/dev/null || \
    busctl --user call org.freedesktop.DBus /org/freedesktop/DBUS \
        org.freedesktop.DBus.StartServiceByName s "org.kde.kwalletd6" >/dev/null || \
    ( echo "    (fallback) launching directly"; \
      [ -x /usr/lib/kf6/kwalletd6 ] && /usr/lib/kf6/kwalletd6 & ) || true
fi

# 2. autostart entry for future logins
AUTODIR=~/.config/autostart
DESK=$AUTODIR/kwalletd6.desktop
if [ ! -f "$DESK" ]; then
    echo "==> installing $DESK"
    mkdir -p "$AUTODIR"
    cat > "$DESK" <<'EOF'
[Desktop Entry]
Type=Application
Name=KWallet Wallet Service
Exec=/usr/lib/kf6/kwalletd6
NoDisplay=true
EOF
    # adapt Exec path if your distro ships kwalletd6 elsewhere
    if [ ! -x /usr/lib/kf6/kwalletd6 ]; then
        ALT="$(command -v kwalletd6 || true)"
        [ -n "$ALT" ] && sed -i "s|^Exec=.*|Exec=$ALT|" "$DESK"
    fi
else
    echo "==> autostart entry already present"
fi

echo
echo "==> NOW fully close the browser (pkill is safest) and start it again."
echo "    The password manager should render your saved passwords."
