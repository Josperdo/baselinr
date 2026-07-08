#!/bin/bash
set -euo pipefail

# --- Colors (disabled automatically when output is not a terminal) ---
if [ -t 1 ]; then
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' YELLOW='' GREEN='' CYAN='' BOLD='' NC=''
fi

function print_section() {
    echo ""
    echo -e "${CYAN}${BOLD}============================================${NC}"
    echo -e "${CYAN}${BOLD}  [*] $1${NC}"
    echo -e "${CYAN}${BOLD}============================================${NC}"
    echo ""
}

# --- Centralized status reporting + summary counters ---
declare -i COUNT_OK=0 COUNT_INFO=0 COUNT_WARN=0 COUNT_FAIL=0

function report() {
    local level="$1" message="$2"
    case "$level" in
        OK)   echo -e "${GREEN}[OK]${NC}   $message"; COUNT_OK=$((COUNT_OK + 1)) ;;
        INFO) echo -e "${CYAN}[INFO]${NC} $message"; COUNT_INFO=$((COUNT_INFO + 1)) ;;
        WARN) echo -e "${YELLOW}[WARN]${NC} $message"; COUNT_WARN=$((COUNT_WARN + 1)) ;;
        FAIL) echo -e "${RED}[FAIL]${NC} $message"; COUNT_FAIL=$((COUNT_FAIL + 1)) ;;
    esac
}

echo -e "${BOLD}${CYAN}"
echo "  ============================================"
echo "        Security Baseline Checker"
echo "  ============================================"
echo -e "${NC}"

function check_users() {
    print_section "Privileged Users"

    # Get users in sudo group
    grep '^sudo:' /etc/group | cut -d: -f4 || true

    # Get users in wheel group (some distros use this)
    grep '^wheel:' /etc/group | cut -d: -f4 2>/dev/null || true
    echo ""
}

function check_password_policy() {
    print_section "Password Policy"

    # Check for password aging and complexity settings
    max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}' || true)
    min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}' || true)
    min_len=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}' || true)
    warn_age=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}' || true)

    if [ -z "$max_days" ]; then
        report INFO "PASS_MAX_DAYS is not set in /etc/login.defs. May be managed by PAM."
    elif [ "$max_days" -gt 90 ]; then
        report WARN "PASS_MAX_DAYS is set to $max_days. Consider setting it to 90 or less for better security."
    elif [ "$max_days" -gt 60 ]; then
        report INFO "PASS_MAX_DAYS is set to $max_days. Consider setting it to 60 or less for enhanced security."
    else
        report OK "PASS_MAX_DAYS is set to $max_days (90 days or less)."
    fi

    if [ -z "$min_days" ]; then
        report INFO "PASS_MIN_DAYS is not set in /etc/login.defs. May be managed by PAM."
    elif [ "$min_days" -eq 0 ]; then
        report WARN "PASS_MIN_DAYS is set to $min_days. Set to 1 or more to prevent password cycling."
    elif [ "$min_days" -lt 14 ]; then
        report INFO "PASS_MIN_DAYS is set to $min_days. Consider setting it to 14 or more for better security."
    else
        report OK "PASS_MIN_DAYS is set to $min_days (14 days or more)."
    fi

    if [ -z "$min_len" ]; then
        report INFO "PASS_MIN_LEN is not set in /etc/login.defs. May be managed by PAM (pam_pwquality)."
    elif [ "$min_len" -lt 8 ]; then
        report WARN "PASS_MIN_LEN is set to $min_len. Consider setting it to 8 or more for stronger passwords."
    else
        report OK "PASS_MIN_LEN is set to $min_len (8 or more)."
    fi

    if [ -z "$warn_age" ]; then
        report INFO "PASS_WARN_AGE is not set in /etc/login.defs. May be managed by PAM."
    elif [ "$warn_age" -lt 7 ]; then
        report WARN "PASS_WARN_AGE is set to $warn_age. Consider setting it to 7 or more for better user experience."
    else
        report OK "PASS_WARN_AGE is set to $warn_age (adequate warning period)."
    fi
    echo ""
}

function check_ssh_config() {
    print_section "SSH Configuration"

    # Check for PermitRootLogin
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
        report WARN "PermitRootLogin is set to yes. Change to no in /etc/ssh/sshd_config and restart SSH."
    elif grep -q "^PermitRootLogin prohibit-password" /etc/ssh/sshd_config; then
        report WARN "PermitRootLogin is set to prohibit-password. Change to no in /etc/ssh/sshd_config and restart SSH."
    elif grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        report OK "PermitRootLogin is set to no."
    else
        report INFO "PermitRootLogin is not explicitly set. Verify the default for your SSH version."
    fi

    # Check for PasswordAuthentication
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
        report WARN "PasswordAuthentication is set to yes. Change to no in /etc/ssh/sshd_config and restart SSH."
    elif grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        report OK "PasswordAuthentication is set to no."
    else
        report INFO "PasswordAuthentication is not explicitly set. Verify."
    fi

    # Check for PermitEmptyPasswords
    if grep -q "^PermitEmptyPasswords yes" /etc/ssh/sshd_config; then
        report FAIL "PermitEmptyPasswords is set to yes. Change to no in /etc/ssh/sshd_config and restart SSH."
    elif grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config; then
        report OK "PermitEmptyPasswords is set to no."
    else
        report INFO "PermitEmptyPasswords is not explicitly set. Verify."
    fi

    # Check for Pubkey Authentication
    if grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config; then
        report OK "PubkeyAuthentication is set to yes."
    elif grep -q "^PubkeyAuthentication no" /etc/ssh/sshd_config; then
        report WARN "PubkeyAuthentication is set to no. Change to yes in /etc/ssh/sshd_config and restart SSH."
    else
        report INFO "PubkeyAuthentication is not explicitly set. Verify."
    fi
    echo ""
}

function check_file_permissions() {
    print_section "File Permissions"

    # Check permissions of critical files
    for file in /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
        if [ -e "$file" ]; then
            perms=$(stat -c "%a %G %U" "$file")
            if [[ "$perms" != "644 root root" && "$file" == "/etc/passwd" ]]; then
                report WARN "$file has permissions $perms. It should be 644 and owned by root:root."
            elif [[ "$perms" != "640 shadow root" && "$file" == "/etc/shadow" ]]; then
                report WARN "$file has permissions $perms. It should be 640 and owned by shadow:root."
            elif [[ "$perms" != "644 root root" && "$file" == "/etc/group" ]]; then
                report WARN "$file has permissions $perms. It should be 644 and owned by root:root."
            elif [[ "$perms" != "440 root root" && "$file" == "/etc/sudoers" ]]; then
                report WARN "$file has permissions $perms. It should be 440 and owned by root:root."
            else
                report OK "$file has secure permissions ($perms)."
            fi
        else
            report WARN "$file does not exist."
        fi
    done
    echo ""
}

function check_capabilities() {
    print_section "File Capabilities"
    # getcap has no -xdev equivalent of its own, so an unrestricted recursive
    # scan can hang on large or slow mounts (NFS shares, attached volumes).
    # Scope the file list with find -xdev instead (requires root for full results).
    local caps
    caps=$(find / -xdev -type f -print0 2>/dev/null | xargs -0 -r getcap 2>/dev/null || true)
    if [ -n "$caps" ]; then
        echo "$caps"
    else
        report INFO "No files with assigned capabilities found on the root filesystem."
    fi
    echo ""
}

function check_suid_sgid() {
    print_section "SUID/SGID Binaries"

    # Binaries commonly shipped with SUID/SGID by default across mainstream distros
    local known_safe=(
        /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn
        /usr/bin/gpasswd /usr/bin/newgrp /usr/bin/mount /usr/bin/umount
        /usr/bin/pkexec /usr/bin/crontab /usr/bin/ping
        /usr/lib/openssh/ssh-keysign /usr/bin/fusermount /usr/bin/fusermount3
    )
    local found=0

    while IFS= read -r -d '' file; do
        found=1
        local perms known=0
        perms=$(stat -c "%A %U:%G" "$file" 2>/dev/null || echo "unknown")
        for safe in "${known_safe[@]}"; do
            [ "$file" = "$safe" ] && known=1 && break
        done
        if [ "$known" -eq 1 ]; then
            report INFO "$file ($perms) — common baseline SUID/SGID binary."
        else
            report WARN "$file ($perms) — SUID/SGID binary outside the common baseline. Review necessity; check against GTFOBins."
        fi
    done < <(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)

    [ "$found" -eq 0 ] && report INFO "No SUID/SGID binaries found on the root filesystem."
    echo ""
}

function check_cron_jobs() {
    print_section "Scheduled Tasks (cron)"

    # System-wide cron paths that execute as root
    local cron_targets=(/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly)
    for target in "${cron_targets[@]}"; do
        [ -e "$target" ] || continue
        while IFS= read -r -d '' file; do
            local perms owner other_bits
            perms=$(stat -c "%a" "$file")
            owner=$(stat -c "%U" "$file")
            other_bits="${perms: -1}"
            if (( other_bits & 2 )); then
                report FAIL "$file is world-writable ($perms, owner $owner). Any local user could plant a root-run cron job."
            elif [ "$owner" != "root" ]; then
                report WARN "$file executes as root via cron but is owned by $owner, not root."
            else
                report OK "$file ($perms, owner $owner)."
            fi
        done < <(find "$target" -maxdepth 1 -type f -print0 2>/dev/null)
    done
    echo ""

    # Per-user crontabs (informational — presence alone isn't a finding)
    local spool_dir=""
    if [ -d /var/spool/cron/crontabs ]; then
        spool_dir=/var/spool/cron/crontabs
    elif [ -d /var/spool/cron ]; then
        spool_dir=/var/spool/cron
    fi

    if [ -n "$spool_dir" ]; then
        local users
        users=$(find "$spool_dir" -maxdepth 1 -type f -printf '%f ' 2>/dev/null || true)
        if [ -n "$users" ]; then
            report INFO "Users with per-user crontabs: $users"
        else
            report INFO "No per-user crontabs found in $spool_dir."
        fi
    else
        report INFO "No per-user crontab spool directory found."
    fi
    echo ""
}

function check_open_ports() {
    print_section "Open Ports & Services"

    # List open ports and associated services
    if ss -tulnp 2>/dev/null | grep -q LISTEN; then
        ss -tulnp || true
    else
        report INFO "No listening ports detected."
    fi
}

function check_firewall() {
    print_section "Firewall"

    # Firewall checks require root to read rules
    if [ "$(id -u)" -ne 0 ]; then
        report INFO "Firewall checks require root privileges. Run with sudo for full results."
        return
    fi

    # Check which firewall is in use and its status
    if command -v ufw >/dev/null 2>&1; then
        report INFO "UFW detected."
        if ufw status | grep -q "Status: active"; then
            # Check default incoming policy
            if ufw status verbose | grep -q "Default: deny (incoming)"; then
                report OK "UFW is active with default incoming policy set to deny."
            elif ufw status verbose | grep -q "Default: allow (incoming)"; then
                report WARN "UFW is active but default incoming policy is allow. Consider changing to deny."
            fi
            echo ""
            echo "Current rules:"
            ufw status verbose || true
        elif ufw status | grep -q "Status: inactive"; then
            report WARN "UFW is installed but inactive. Consider enabling it for better security."
        else
            report INFO "UFW status could not be determined. Please check manually."
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        report INFO "firewalld detected."
        firewall-cmd --state || true
        echo "Current firewall rules:"
        firewall-cmd --list-all || true
    elif command -v iptables >/dev/null 2>&1; then
        report INFO "iptables detected."
        # Check for dangerous default ACCEPT policy first (specific before general)
        if iptables -L INPUT -n | head -1 | grep -q "policy ACCEPT"; then
            report WARN "iptables INPUT chain has default ACCEPT policy. Consider changing to DROP and adding explicit allow rules."
        elif iptables -L INPUT -n | head -1 | grep -q "policy DROP"; then
            report OK "iptables INPUT chain has default DROP policy."
        fi
        echo ""
        echo "Current rules:"
        iptables -L -n -v || true
    else
        report WARN "No common firewall management tool detected (ufw, firewalld, iptables)."
    fi
    echo ""
}

function check_unattended_upgrades() {
    print_section "Automatic Updates"

    # Check for unattended upgrade tools based on package manager
    if command -v dpkg >/dev/null 2>&1; then
        if dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; then
            report INFO "Unattended Upgrades is installed."
            if grep -q 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
                report OK "Unattended Upgrades is enabled to automatically install security updates."
            else
                report WARN "Unattended Upgrades is installed but not enabled. Consider enabling it to automatically install security updates."
            fi
        else
            report INFO "Unattended Upgrades is not installed. Consider installing it to automatically install security updates."
        fi
    elif command -v rpm >/dev/null 2>&1; then
        if rpm -q dnf-automatic >/dev/null 2>&1; then
            report INFO "DNF Automatic is installed."
            if systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then
                report OK "DNF Automatic is enabled to automatically install security updates."
            else
                report WARN "DNF Automatic is installed but not enabled. Consider enabling it to automatically install security updates."
            fi
        else
            report INFO "DNF Automatic is not installed. Consider installing it to automatically install security updates."
        fi
    else
        report INFO "Could not determine package manager. Please check for unattended upgrade tools manually."
    fi
    echo ""
}

function print_summary() {
    print_section "Summary"
    echo -e "${GREEN}OK:${NC}   $COUNT_OK"
    echo -e "${CYAN}INFO:${NC} $COUNT_INFO"
    echo -e "${YELLOW}WARN:${NC} $COUNT_WARN"
    echo -e "${RED}FAIL:${NC} $COUNT_FAIL"

    local scored=$((COUNT_OK + COUNT_WARN + COUNT_FAIL))
    if [ "$scored" -gt 0 ]; then
        local score=$((COUNT_OK * 100 / scored))
        echo ""
        echo -e "${BOLD}Baseline Score: ${score}%${NC}  (${COUNT_OK}/${scored} checks passing; INFO findings excluded from scoring)"
    fi
    echo ""
}

check_users
check_password_policy
check_ssh_config
check_file_permissions
check_capabilities
check_suid_sgid
check_cron_jobs
check_open_ports
check_firewall
check_unattended_upgrades
print_summary

echo -e "${BOLD}${CYAN}"
echo "  ============================================"
echo "              Check Complete"
echo "  ============================================"
echo -e "${NC}"
