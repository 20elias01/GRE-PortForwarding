#!/bin/bash

# ==============================================================
#              ELIAS GRE TUNNEL MANAGER
#        Persistent • Selective TCP/UDP Forwarding
#
#   GRE:
#       Iran    : 132.168.30.2
#       Foreign : 132.168.30.1
#
#   IMPORTANT:
#       Only selected ports are forwarded.
#       No global DNAT.
#       No global MASQUERADE.
# ==============================================================

set -u

# ==============================================================
# COLORS
# ==============================================================

C_RESET='\033[0m'
C_BOLD='\033[1m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[0;34m'
C_MAGENTA='\033[0;35m'
C_CYAN='\033[0;36m'
C_WHITE='\033[1;37m'
C_GRAY='\033[0;90m'

# ==============================================================
# VARIABLES
# ==============================================================

GRE_NAME="vatan-m2"

IRAN_GRE_IP="132.168.30.2"
FOREIGN_GRE_IP="132.168.30.1"
GRE_NET="132.168.30.0/30"

BASE_DIR="/etc/elias-gre"
CONFIG_FILE="${BASE_DIR}/config"
SERVICE_FILE="/etc/systemd/system/elias-gre.service"
SERVICE_HELPER="/usr/local/sbin/elias-gre-service"

NAT_DNAT_CHAIN="ELIAS_GRE_DNAT"
NAT_MASQ_CHAIN="ELIAS_GRE_MASQ"
FWD_CHAIN="ELIAS_GRE_FORWARD"

# ==============================================================
# UI
# ==============================================================

clear

banner() {
    echo -e "${C_CYAN}"
    echo "╔════════════════════════════════════════════╗"
    echo "║        GRE-PortForwarding - EliasVPN       ║"
    echo "║           Persistent • Easy Setup          ║"
    echo "╚════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
}

line() {
    echo -e "${C_GRAY}──────────────────────────────────────────────────────────${C_RESET}"
}

ok() {
    echo -e "${C_GREEN}  ✔️ $1${C_RESET}"
}

info() {
    echo -e "${C_CYAN}  • $1${C_RESET}"
}

warn() {
    echo -e "${C_YELLOW}  ! $1${C_RESET}"
}

error_msg() {
    echo -e "${C_RED}  ✖️ $1${C_RESET}"
}

# ==============================================================
# ROOT
# ==============================================================

if [[ $EUID -ne 0 ]]; then
    error_msg "This script must be run as root."
    exit 1
fi

# ==============================================================
# VALIDATION
# ==============================================================

validate_ip() {
    local ip="$1"

    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    IFS='.' read -r a b c d <<< "$ip"

    ((a <= 255 && b <= 255 && c <= 255 && d <= 255))
}

validate_port() {
    local p="$1"

    [[ "$p" =~ ^[0-9]+$ ]] &&
    ((p >= 1 && p <= 65535))
}


normalize_ports() {

    local input="$1"
    local output=""
    local p

    # Convert comma-separated ports to space-separated
    input="${input//,/ }"

    for p in $input; do

        if ! validate_port "$p"; then
            error_msg "Invalid port: $p"
            return 1
        fi

        if [[ ! " $output " =~ " $p " ]]; then
            output="${output:+$output }$p"
        fi

    done

    [[ -n "$output" ]] || return 1

    echo "$output"
}


# ==============================================================
# SYSCTL
# ==============================================================

save_previous_forwarding_state() {

    mkdir -p "$BASE_DIR"

    if [[ ! -f "${CONFIG_FILE}.ip_forward" ]]; then

        local current

        current=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)

        echo "$current" > "${CONFIG_FILE}.ip_forward"

    fi
}

enable_forwarding() {

    sysctl -w net.ipv4.ip_forward=1 >/dev/null

}

restore_forwarding() {

    local old="0"

    if [[ -f "${CONFIG_FILE}.ip_forward" ]]; then
        old=$(cat "${CONFIG_FILE}.ip_forward")
    fi

    if [[ "$old" != "1" ]]; then
        sysctl -w net.ipv4.ip_forward=0 >/dev/null
    else
        sysctl -w net.ipv4.ip_forward=1 >/dev/null
    fi
}

# ==============================================================
# IPTABLES CHAIN HELPERS
# ==============================================================

remove_jump_if_exists() {

    local table="$1"
    local chain="$2"
    local target="$3"

    while iptables -t "$table" -C "$chain" -j "$target" 2>/dev/null; do
        iptables -t "$table" -D "$chain" -j "$target" 2>/dev/null || break
    done
}

create_chain() {

    local table="$1"
    local chain="$2"

    iptables -t "$table" -N "$chain" 2>/dev/null || true
    iptables -t "$table" -F "$chain"
}

# ==============================================================
# CLEAN OUR OLD RULES
# ==============================================================

cleanup_iptables() {

    info "Removing previous ELIAS GRE firewall rules..."

    # Remove jumps from built-in chains

    remove_jump_if_exists nat PREROUTING "$NAT_DNAT_CHAIN"
    remove_jump_if_exists nat POSTROUTING "$NAT_MASQ_CHAIN"
    remove_jump_if_exists filter FORWARD "$FWD_CHAIN"

    # Flush + delete custom chains

    iptables -t nat -F "$NAT_DNAT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$NAT_DNAT_CHAIN" 2>/dev/null || true

    iptables -t nat -F "$NAT_MASQ_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$NAT_MASQ_CHAIN" 2>/dev/null || true

    iptables -F "$FWD_CHAIN" 2>/dev/null || true
    iptables -X "$FWD_CHAIN" 2>/dev/null || true

}

# ==============================================================
# CREATE SELECTIVE IPTABLES
# ==============================================================

setup_iptables_iran() {

    local ports="$1"

    cleanup_iptables

    create_chain nat "$NAT_DNAT_CHAIN"
    create_chain nat "$NAT_MASQ_CHAIN"
    create_chain filter "$FWD_CHAIN"

    # Attach our chains once

    iptables -t nat -A PREROUTING -j "$NAT_DNAT_CHAIN"
    iptables -t nat -A POSTROUTING -j "$NAT_MASQ_CHAIN"
    iptables -A FORWARD -j "$FWD_CHAIN"

    local p

    for p in $ports; do

        # ------------------------------------------------------
        # TCP DNAT
        # ------------------------------------------------------

        iptables -t nat -A "$NAT_DNAT_CHAIN" \
            -p tcp \
            --dport "$p" \
            -j DNAT \
            --to-destination "${FOREIGN_GRE_IP}:${p}"

        # ------------------------------------------------------
        # UDP DNAT
        # ------------------------------------------------------

        iptables -t nat -A "$NAT_DNAT_CHAIN" \
            -p udp \
            --dport "$p" \
            -j DNAT \
            --to-destination "${FOREIGN_GRE_IP}:${p}"

        # ------------------------------------------------------
        # TCP MASQUERADE
        # ------------------------------------------------------

        iptables -t nat -A "$NAT_MASQ_CHAIN" \
            -o "$GRE_NAME" \
            -p tcp \
            -d "$FOREIGN_GRE_IP" \
            --dport "$p" \
            -j MASQUERADE

        # ------------------------------------------------------
        # UDP MASQUERADE
        # ------------------------------------------------------

        iptables -t nat -A "$NAT_MASQ_CHAIN" \
            -o "$GRE_NAME" \
            -p udp \
            -d "$FOREIGN_GRE_IP" \
            --dport "$p" \
            -j MASQUERADE

        # ------------------------------------------------------
        # TCP FORWARD
        # ------------------------------------------------------

        iptables -A "$FWD_CHAIN" \
            -i eth0 \
            -o "$GRE_NAME" \
            -p tcp \
            -d "$FOREIGN_GRE_IP" \
            --dport "$p" \
            -m conntrack \
            --ctstate NEW,ESTABLISHED \
            -j ACCEPT

        iptables -A "$FWD_CHAIN" \
            -i "$GRE_NAME" \
            -o eth0 \
            -p tcp \
            -s "$FOREIGN_GRE_IP" \
            --sport "$p" \
            -m conntrack \
            --ctstate ESTABLISHED \
            -j ACCEPT

        # ------------------------------------------------------
        # UDP FORWARD
        # ------------------------------------------------------

        iptables -A "$FWD_CHAIN" \
            -i eth0 \
            -o "$GRE_NAME" \
            -p udp \
            -d "$FOREIGN_GRE_IP" \
            --dport "$p" \
            -j ACCEPT

        iptables -A "$FWD_CHAIN" \
            -i "$GRE_NAME" \
            -o eth0 \
            -p udp \
            -s "$FOREIGN_GRE_IP" \
            --sport "$p" \
            -j ACCEPT

    done

}

# ==============================================================
# GRE CREATION - IRAN
# ==============================================================

create_gre_iran() {

    local iran_ip="$1"
    local foreign_ip="$2"

    ip link set "$GRE_NAME" down 2>/dev/null || true
    ip tunnel del "$GRE_NAME" 2>/dev/null || true

    ip tunnel add "$GRE_NAME" \
        mode gre \
        local "$iran_ip" \
        remote "$foreign_ip" \
        ttl 255

    ip addr add "${IRAN_GRE_IP}/30" dev "$GRE_NAME"

    ip link set "$GRE_NAME" mtu 1476
    ip link set "$GRE_NAME" up

}

# ==============================================================
# GRE CREATION - FOREIGN
# ==============================================================

create_gre_foreign() {

    local iran_ip="$1"
    local foreign_ip="$2"

    ip link set "$GRE_NAME" down 2>/dev/null || true
    ip tunnel del "$GRE_NAME" 2>/dev/null || true

    ip tunnel add "$GRE_NAME" \
        mode gre \
        local "$foreign_ip" \
        remote "$iran_ip" \
        ttl 255

    ip addr add "${FOREIGN_GRE_IP}/30" dev "$GRE_NAME"

    ip link set "$GRE_NAME" mtu 1476
    ip link set "$GRE_NAME" up

}

# ==============================================================
# SAVE CONFIG
# ==============================================================

save_config() {

    local role="$1"
    local iran_ip="$2"
    local foreign_ip="$3"
    local ports="$4"

    mkdir -p "$BASE_DIR"

    cat > "$CONFIG_FILE" <<EOF
ROLE="$role"
IRAN_IP="$iran_ip"
FOREIGN_IP="$foreign_ip"
PORTS="$ports"
EOF

}

# ==============================================================
# SERVICE HELPER
# ==============================================================

install_service_helper() {

    mkdir -p "$(dirname "$SERVICE_HELPER")"

    cat > "$SERVICE_HELPER" <<'EOF'
#!/bin/bash

set -u

CONFIG_FILE="/etc/elias-gre/config"
GRE_NAME="vatan-m2"

IRAN_GRE_IP="132.168.30.2"
FOREIGN_GRE_IP="132.168.30.1"

NAT_DNAT_CHAIN="ELIAS_GRE_DNAT"
NAT_MASQ_CHAIN="ELIAS_GRE_MASQ"
FWD_CHAIN="ELIAS_GRE_FORWARD"

[[ -f "$CONFIG_FILE" ]] || exit 1

source "$CONFIG_FILE"

remove_jump_if_exists() {

    local table="$1"
    local chain="$2"
    local target="$3"

    while iptables -t "$table" -C "$chain" -j "$target" 2>/dev/null; do
        iptables -t "$table" -D "$chain" -j "$target" 2>/dev/null || break
    done
}

cleanup_iptables() {

    remove_jump_if_exists nat PREROUTING "$NAT_DNAT_CHAIN"
    remove_jump_if_exists nat POSTROUTING "$NAT_MASQ_CHAIN"
    remove_jump_if_exists filter FORWARD "$FWD_CHAIN"

    iptables -t nat -F "$NAT_DNAT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$NAT_DNAT_CHAIN" 2>/dev/null || true

    iptables -t nat -F "$NAT_MASQ_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$NAT_MASQ_CHAIN" 2>/dev/null || true

    iptables -F "$FWD_CHAIN" 2>/dev/null || true
    iptables -X "$FWD_CHAIN" 2>/dev/null || true
}

create_chain() {

    local table="$1"
    local chain="$2"

    iptables -t "$table" -N "$chain" 2>/dev/null || true
    iptables -t "$table" -F "$chain"
}

# --------------------------------------------------------------
# Wait for network
# --------------------------------------------------------------

for i in {1..30}; do

    if ip link show "$GRE_NAME" >/dev/null 2>&1; then
        ip link set "$GRE_NAME" down 2>/dev/null || true
        ip tunnel del "$GRE_NAME" 2>/dev/null || true
    fi

    if ip route get "$FOREIGN_IP" >/dev/null 2>&1; then
        break
    fi

    sleep 2

done

# --------------------------------------------------------------
# Recreate GRE
# --------------------------------------------------------------

if [[ "$ROLE" == "IRAN" ]]; then

    ip tunnel add "$GRE_NAME" \
        mode gre \
        local "$IRAN_IP" \
        remote "$FOREIGN_IP" \
        ttl 255

    ip addr add "${IRAN_GRE_IP}/30" dev "$GRE_NAME"

else

    ip tunnel add "$GRE_NAME" \
        mode gre \
        local "$FOREIGN_IP" \
        remote "$IRAN_IP" \
        ttl 255

    ip addr add "${FOREIGN_GRE_IP}/30" dev "$GRE_NAME"

fi

ip link set "$GRE_NAME" mtu 1476
ip link set "$GRE_NAME" up

# --------------------------------------------------------------
# Forwarding
# --------------------------------------------------------------

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# --------------------------------------------------------------
# Iran firewall rules
# --------------------------------------------------------------

if [[ "$ROLE" == "IRAN" ]]; then

    cleanup_iptables

    create_chain nat "$NAT_DNAT_CHAIN"
    create_chain nat "$NAT_MASQ_CHAIN"
    create_chain filter "$FWD_CHAIN"

    iptables -t nat -A PREROUTING -j "$NAT_DNAT_CHAIN"
    iptables -t nat -A POSTROUTING -j "$NAT_MASQ_CHAIN"
    iptables -A FORWARD -j "$FWD_CHAIN"

    for p in $PORTS; do

        iptables -t nat -A "$NAT_DNAT_CHAIN" \
            -p tcp \
            --dport "$p" \
            -j DNAT \
            --to-destination "${FOREIGN_GRE_IP}:${p}"

        iptables -t nat -A "$NAT_DNAT_CHAIN" \
            -p udp \
            --dport "$p" \
            -j DNAT \
            --to-destination "${FOREIGN_GRE_IP}:${p}"

        iptables -t nat -A "$NAT_MASQ_CHAIN" \
            -o "$GRE_NAME" \
            -p tcp \
            -d "$FOREIGN_GRE_IP" \
            --dport "$p" \
            -j MASQUERADE

        iptables -t nat -A "$NAT_MASQ_CHAIN" \
            -o "$GRE_NAME" \
            -p udp \
            -d "$FOREIGN_GRE_IP" \
            --dport "$p" \
            -j MASQUERADE

        iptables -A "$FWD_CHAIN" \
            -i eth0 \
            -o "$GRE_NAME" \
            -p tcp \
            -d "$FOREIGN_GRE_IP" \
            --dport "$p" \
            -m conntrack \
            --ctstate NEW,ESTABLISHED \
            -j ACCEPT

        iptables -A "$FWD_CHAIN" \
            -i "$GRE_NAME" \
            -o eth0 \
            -p tcp \
            -s "$FOREIGN_GRE_IP" \
            --sport "$p" \
            -m conntrack \
            --ctstate ESTABLISHED \
            -j ACCEPT

        iptables -A "$FWD_CHAIN" \
            -i eth0 \
            -o "$GRE_NAME" \
            -p udp \
            -d "$FOREIGN_GRE_IP" \
            --dport "$p" \
            -j ACCEPT

        iptables -A "$FWD_CHAIN" \
            -i "$GRE_NAME" \
            -o eth0 \
            -p udp \
            -s "$FOREIGN_GRE_IP" \
            --sport "$p" \
            -j ACCEPT

    done

fi

exit 0
EOF

    chmod 700 "$SERVICE_HELPER"
}

# ==============================================================
# SYSTEMD SERVICE
# ==============================================================

install_systemd_service() {

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=ELIAS GRE Tunnel and Selective Port Forwarding
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SERVICE_HELPER
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable elias-gre.service >/dev/null 2>&1
}

# ==============================================================
# REMOVE EVERYTHING
# ==============================================================

complete_remove() {

    echo
    line
    echo -e "${C_RED}${C_BOLD}             COMPLETE REMOVAL${C_RESET}"
    line
    echo

    warn "This will remove only components created by ELIAS GRE."

    echo
    read -p "Type REMOVE to continue: " CONFIRM

    if [[ "$CONFIRM" != "REMOVE" ]]; then
        echo
        warn "Cancelled."
        exit 0
    fi

    echo

    # Stop service first
    systemctl stop elias-gre.service 2>/dev/null || true
    systemctl disable elias-gre.service 2>/dev/null || true

    # Remove firewall rules belonging to us
    cleanup_iptables

    # Remove GRE
    ip link set "$GRE_NAME" down 2>/dev/null || true
    ip tunnel del "$GRE_NAME" 2>/dev/null || true
    ip link delete "$GRE_NAME" 2>/dev/null || true

    # Restore previous IP forwarding state
    restore_forwarding

    # Remove systemd
    rm -f "$SERVICE_FILE"

    # Remove helper
    rm -f "$SERVICE_HELPER"

    # Remove configuration
    rm -rf "$BASE_DIR"

    systemctl daemon-reload
    systemctl reset-failed elias-gre.service 2>/dev/null || true

    echo
    ok "GRE interface removed."
    ok "ELIAS iptables chains removed."
    ok "Selective forwarding rules removed."
    ok "systemd service removed."
    ok "Configuration removed."
    ok "Previous ip_forward state restored."
    echo
    echo -e "${C_GREEN}${C_BOLD}✓ Complete removal finished.${C_RESET}"
    echo

    exit 0
}

# ==============================================================
# SETUP IRAN
# ==============================================================

setup_iran() {

    echo
    echo -e "${C_CYAN}${C_BOLD}  IRAN SERVER SETUP${C_RESET}"
    line
    echo

    read -p "Iran Public IP    : " IP_IRAN
    read -p "Foreign Public IP : " IP_FOREIGN

    if ! validate_ip "$IP_IRAN"; then
        error_msg "Invalid Iran IP."
        exit 1
    fi

    if ! validate_ip "$IP_FOREIGN"; then
        error_msg "Invalid Foreign IP."
        exit 1
    fi

    echo
    echo -e "${C_YELLOW}Enter the ports you want to forward.${C_RESET}"
    echo -e "${C_GRAY}Example: 51820${C_RESET}"
    echo -e "${C_GRAY}Example: 443 8443 2053 51820${C_RESET}"
    echo
    echo -e "${C_WHITE}Each selected port will support BOTH TCP and UDP.${C_RESET}"
    echo

    read -p "Forward ports : " RAW_PORTS

    PORTS=$(normalize_ports "$RAW_PORTS") || {
        error_msg "Invalid port list."
        exit 1
    }

    echo
    line
    echo -e "${C_WHITE}${C_BOLD}Configuration Summary${C_RESET}"
    line
    echo
    info "Iran    : $IP_IRAN"
    info "Foreign : $IP_FOREIGN"
    info "GRE     : $IRAN_GRE_IP  →  $FOREIGN_GRE_IP"
    echo
    echo -e "${C_GREEN}${C_BOLD}Forwarded ports:${C_RESET}"

    for p in $PORTS; do
        echo -e "  ${C_CYAN}TCP/$p${C_RESET}"
        echo -e "  ${C_CYAN}UDP/$p${C_RESET}"
    done

    echo
    warn "All other ports remain local on the Iran server."
    echo

    read -p "Continue? [y/N]: " CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        warn "Cancelled."
        exit 0
    fi

    echo
    info "Saving previous forwarding state..."
    save_previous_forwarding_state

    info "Enabling IPv4 forwarding..."
    enable_forwarding

    info "Creating GRE interface..."
    create_gre_iran "$IP_IRAN" "$IP_FOREIGN"

    info "Installing selective forwarding rules..."
    setup_iptables_iran "$PORTS"

    save_config "IRAN" "$IP_IRAN" "$IP_FOREIGN" "$PORTS"

    info "Installing persistent systemd service..."
    install_service_helper
    install_systemd_service

    systemctl restart elias-gre.service

    echo
    line
    echo -e "${C_GREEN}${C_BOLD}              SETUP COMPLETE${C_RESET}"
    line
    echo
    ok "GRE tunnel is UP."
    ok "Only selected ports are forwarded."
    ok "TCP + UDP forwarding enabled."
    ok "Persistent after reboot."
    echo
    info "GRE local  : $IRAN_GRE_IP"
    info "GRE remote : $FOREIGN_GRE_IP"
    echo
    echo -e "${C_YELLOW}Forwarding:${C_RESET}"

    for p in $PORTS; do
        echo -e "  ${C_GREEN}TCP/$p${C_RESET}  →  ${FOREIGN_GRE_IP}:$p"
        echo -e "  ${C_GREEN}UDP/$p${C_RESET}  →  ${FOREIGN_GRE_IP}:$p"
    done

    echo
    line
    echo -e "${C_CYAN}Useful test:${C_RESET}"
    echo -e "  ping -I $GRE_NAME -c 4 $FOREIGN_GRE_IP"
    echo
}

# ==============================================================
# SETUP FOREIGN
# ==============================================================

setup_foreign() {

    echo
    echo -e "${C_MAGENTA}${C_BOLD}  FOREIGN SERVER SETUP${C_RESET}"
    line
    echo

    read -p "Iran Public IP    : " IP_IRAN
    read -p "Foreign Public IP : " IP_FOREIGN

    if ! validate_ip "$IP_IRAN"; then
        error_msg "Invalid Iran IP."
        exit 1
    fi

    if ! validate_ip "$IP_FOREIGN"; then
        error_msg "Invalid Foreign IP."
        exit 1
    fi

    echo
    echo -e "${C_YELLOW}Enter the SAME ports configured on Iran.${C_RESET}"
    echo -e "${C_GRAY}Example: 51820${C_RESET}"
    echo -e "${C_GRAY}Example: 443 8443 2053 51820${C_RESET}"
    echo

    read -p "Forward ports : " RAW_PORTS

    PORTS=$(normalize_ports "$RAW_PORTS") || {
        error_msg "Invalid port list."
        exit 1
    }

    echo
    line
    echo -e "${C_WHITE}${C_BOLD}Configuration Summary${C_RESET}"
    line
    echo
    info "Iran    : $IP_IRAN"
    info "Foreign : $IP_FOREIGN"
    info "GRE     : $FOREIGN_GRE_IP  →  $IRAN_GRE_IP"
    echo
    echo -e "${C_GREEN}${C_BOLD}Expected service ports:${C_RESET}"

    for p in $PORTS; do
        echo -e "  ${C_CYAN}TCP/$p${C_RESET}"
        echo -e "  ${C_CYAN}UDP/$p${C_RESET}"
    done

    echo

    read -p "Continue? [y/N]: " CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        warn "Cancelled."
        exit 0
    fi

    echo

    info "Saving previous forwarding state..."
    save_previous_forwarding_state

    info "Enabling IPv4 forwarding..."
    enable_forwarding

    info "Creating GRE interface..."
    create_gre_foreign "$IP_IRAN" "$IP_FOREIGN"

    save_config "FOREIGN" "$IP_IRAN" "$IP_FOREIGN" "$PORTS"

    info "Installing persistent systemd service..."
    install_service_helper
    install_systemd_service

    systemctl restart elias-gre.service

    echo
    line
    echo -e "${C_GREEN}${C_BOLD}              SETUP COMPLETE${C_RESET}"
    line
    echo
    ok "GRE tunnel is UP."
    ok "Configuration saved."
    ok "Persistent after reboot."
    echo
    info "GRE local  : $FOREIGN_GRE_IP"
    info "GRE remote : $IRAN_GRE_IP"
    echo

    echo -e "${C_YELLOW}Services should listen on:${C_RESET}"

    for p in $PORTS; do
        echo -e "  ${C_GREEN}$FOREIGN_GRE_IP:$p${C_RESET}  (TCP + UDP)"
    done

    echo
    line
    echo -e "${C_CYAN}GRE test:${C_RESET}"
    echo -e "  ping -c 4 $IRAN_GRE_IP"
    echo
}

# ==============================================================
# MENU
# ==============================================================

banner

echo
echo -e "${C_WHITE}${C_BOLD}Select an operation:${C_RESET}"
echo
echo -e "  ${C_GREEN}1${C_RESET}  Setup GRE on ${C_YELLOW}IRAN${C_RESET}"
echo -e "  ${C_GREEN}2${C_RESET}  Setup GRE on ${C_MAGENTA}FOREIGN${C_RESET}"
echo -e "  ${C_RED}3${C_RESET}  Complete Remove"
echo
line
read -p "  Your choice [1-3]: " CHOICE

case "$CHOICE" in

    1)
        setup_iran
        ;;

    2)
        setup_foreign
        ;;

    3)
        complete_remove
        ;;

    *)
        error_msg "Invalid choice."
        exit 1
        ;;

esac

echo -e "${C_CYAN}${C_BOLD}Done.${C_RESET}"



