#!/usr/bin/env bash
# Strict mode. Remove -e if it causes the environment-specific pct create failure.
set -euo pipefail

# Verbose mode
VERBOSE=1

# Utility: print verbose
vprint() { [ "${VERBOSE:-0}" -gt 0 ] && printf '%s\n' "$*"; }

# ---------- Container parameters (tweak as needed) ----------
CT_ID="900"                     # starting ID; script will bump if in use
CT_hostname="vaultwarden"
CT_network_suffix=".lan"
CT_root_password="qwerty"       # change to a secure password (or unset to use key-only)
CT_memory="1024"                # MB
CT_cores="4"
CT_rootfs_size="20G"            # Must be large enough for Docker images / data
CT_install_packages="sudo screen wget htop docker-compose authbind"
CT_enable_root_login="true"
CT_template_download="http://download.proxmox.com/images/system/debian-12-standard_12.7-1_amd64.tar.zst"
CT_template_filename="debian-12-standard_12.7-1_amd64.tar.zst"
CT_template_file="local:vztmpl/$CT_template_filename"
CT_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8Eg5xSbsyLySMCH5K1eb8ZzLTLwPrXDmgyGh9OAi/kofhR6UrTtuVzViAxBV8i+52pgMkRFoX2q/wDKkX7bJk0HXGzs26Npz40BCOEO6hf8MlTc/Kdu288sxVKPhnMofJ1UGy4vZjy2AHoAEe0NbazoEiBNZNO+EpXAGnaxnSM2KQFDDidZydeFMaGKWPb0wYXnGeKbnjxA2rASbX2Rd515FC5ZkYVAK0KFjRV41q+xJebBDhGhgLpHynusmFINM/RdoUswD+c2lwRpdIL+yU+DIPt4J7pM6h0Tj8hTFlqIzemwKKFi4UkzL53oQFYpCK2qAHiBTHAfOdL8gcF5Kv rsa-key-20240131"

# ---------- Internal collections ----------
declare -a NET_CONFIGS=()       # each entry is a single --netN name=...,param=...
declare -a USER_NAMES=()        # username
declare -a USER_PRIMARY_GROUP=()# primary group or empty
declare -a USER_SHELL=()        # shell path or empty
declare -a USER_PASSWORD=()     # password string; "!" means nopassword marker
declare -a USER_GROUPS_EXTRA=() # supplementary groups string (comma or space separated)
declare -a USER_LOCK=()         # "true" or empty

declare -a FILE_PATHS=()        # target path inside container
declare -a FILE_PERMS=()        # optional permission
declare -a FILE_OWNER=()        # optional owner
# file contents are stored as elements of a single array of multiline strings
declare -a FILE_CONTENTS=()

declare -a PORT_BINDS=()        # entries like "443:username"
declare -a COMMANDS=()          # commands to run inside container after provisioning

# ---------- Helper functions ----------
pct_exec() {
  # Execute a command inside the container via pct exec.
  # Usage: pct_exec "command with args and single-quoted strings if needed"
  local cmd="$*"
  vprint "pct exec $CT_ID -- /bin/sh -c '$cmd'"
  pct exec "$CT_ID" -- /bin/sh -c "$cmd"
}

pct_install_package() {
  local packages="$*"
  case "${CT_os_type:-debian}" in
    centos|almalinux|amazonlinux|openeuler|oracle|rockylinux|springdalelinux)
      install_command="yum install -y"
      ;;
    debian|devuan|kali|ubuntu|mint)
      install_command="apt -qq install -y"
      ;;
    alpine)
      install_command="apk add --quiet"
      ;;
    archlinux)
      install_command="pacman --noconfirm -S"
      ;;
    fedora)
      install_command="dnf install -y"
      ;;
    gentoo|funtoo)
      install_command="emerge --quiet"
      ;;
    opensuse)
      install_command="zypper --quiet install -y"
      ;;
    nixos)
      install_command="nix-env -i"
      ;;
    openwrt|busybox)
      install_command="opkg install"
      ;;
    voidlinux)
      install_command="xbps-install -y"
      ;;
    slackware)
      install_command="slackpkg install"
      ;;
    plamo)
      install_command="pkginstall"
      ;;
    alt)
      install_command="apt-get install -y"
      ;;
    *)
      echo "Error: Unknown or unsupported OS type '$CT_os_type'." >&2
      return 1
      ;;
  esac
  pct_exec "$install_command $packages"
}

pct_update_package_manager() {
  case "${CT_os_type:-debian}" in
    centos|almalinux|amazonlinux|openeuler|oracle|rockylinux|springdalelinux)
      pct_exec "yum -q -y update"
      ;;
    debian|devuan|kali|ubuntu|mint)
      pct_exec "apt -qq update"
      ;;
    alpine)
      pct_exec "apk update"
      ;;
    archlinux)
      pct_exec "pacman -Sy --noconfirm"
      ;;
    fedora)
      pct_exec "dnf -q -y update"
      ;;
    gentoo|funtoo)
      pct_exec "emerge --sync"
      ;;
    opensuse)
      pct_exec "zypper --gpg-auto-import-keys refresh"
      ;;
    nixos)
      pct_exec "nix-channel --update && nix-env -u '*'"
      ;;
    openwrt|busybox)
      pct_exec "opkg update"
      ;;
    voidlinux)
      pct_exec "xbps-install -Sy"
      ;;
    slackware)
      pct_exec "slackpkg update"
      ;;
    plamo)
      pct_exec "pkginstall --update"
      ;;
    alt)
      pct_exec "apt-get update"
      ;;
    *)
      echo "Error: Unknown or unsupported OS type '$CT_os_type'. Cannot update package manager." >&2
      return 1
      ;;
  esac
}

# write a string into a file inside the container, preserving expanded variables local to host
# Behavior: text is expanded locally then streamed into container path (append or overwrite)
# Usage: write_into_container_file "/path/in/container" "here line1\nline2" "append|overwrite"
write_into_container_file() {
  local dest="$1"; local content="$2"; local mode="${3:-append}"
  if [ "$mode" != "append" ] && [ "$mode" != "overwrite" ]; then
    echo "write_into_container_file: invalid mode: $mode" >&2
    return 2
  fi
  if [ "$mode" = "overwrite" ]; then
    # create parent dir first
    pct_exec "mkdir -p \"$(dirname "$dest")\""
    printf '%s\n' "$content" | pct exec "$CT_ID" -- /bin/sh -c "cat > \"$dest\""
  else
    pct_exec "mkdir -p \"$(dirname "$dest")\""
    printf '%s\n' "$content" | pct exec "$CT_ID" -- /bin/sh -c "cat >> \"$dest\""
  fi
}

pct_set_password() {
  # Accepts args like "user:password"
  for user_pass in "$@"; do
    user="${user_pass%%:*}"
    pass="${user_pass#*:}"
    # Using chpasswd, avoid nested quoting issues by passing the string through printf into pct exec
    printf '%s\n' "${user}:${pass}" | pct exec "$CT_ID" -- /bin/sh -c "cat | chpasswd"
  done
}

# ---------- Add functions to build lists ----------

addnet() {
  # Usage: addnet <name> [key value]...
  # Valid params set
  local valid_params=(bridge firewall gw gw6 hwaddr ip ip6 link_down mtu rate tag trunks type)
  local name="$1"; shift
  local cfg="name=$name"
  while [ $# -gt 0 ]; do
    local key="$1"; local val="${2:-}"
    # check valid
    local ok=0
    for p in "${valid_params[@]}"; do [ "$p" = "$key" ] && ok=1 && break; done
    if [ $ok -eq 1 ]; then
      cfg="$cfg,$key=$val"
      shift 2
    else
      shift 1
    fi
  done
  NET_CONFIGS+=("$cfg")
  vprint "Interface added: $cfg"
}

adduser() {
  # Usage: adduser "username[:primarygroup]" [nologin] [shell <path>] [groups <g1,g2>] [nopassword|password <pwd>] [lock]
  local spec="$1"; shift
  local username="${spec%%:*}"
  local primary_group=""
  [ "$spec" != "$username" ] && primary_group="${spec#*:}"
  local shell=""
  local password=""      # empty means no password set; set to "!" for nopassword marker as in your original
  local groups_extra=""
  local lock=""
  while [ $# -gt 0 ]; do
    case "$1" in
      nologin) shell="/usr/sbin/nologin"; shift ;;
      shell) shift; shell="$1"; shift ;;
      groups) shift; groups_extra="$1"; shift ;;
      nopassword) password="!" ; shift ;;
      password) shift; password="$1"; shift ;;
      lock) lock="true"; shift ;;
      *) vprint "Warning: Unrecognized user option '$1'"; shift ;;
    esac
  done
  USER_NAMES+=("$username")
  USER_PRIMARY_GROUP+=("$primary_group")
  USER_SHELL+=("$shell")
  USER_PASSWORD+=("$password")
  USER_GROUPS_EXTRA+=("$groups_extra")
  USER_LOCK+=("$lock")
}

addfile() {
  # Usage: addfile "/path" "perm" "owner" "multiline content"
  local path="$1"; local perm="${2:-}"; local owner="${3:-}"; local content="${4:-}"
  FILE_PATHS+=("$path")
  FILE_PERMS+=("$perm")
  FILE_OWNER+=("$owner")
  FILE_CONTENTS+=("$content")
}

addline_to_file() {
  # Convenience: append a single line to the last added file's content
  # Usage: addline_to_file "the line"
  local line="$1"
  local idx=$(( ${#FILE_CONTENTS[@]} - 1 ))
  if [ $idx -lt 0 ]; then
    echo "addline_to_file: no file to add line to" >&2
    return 1
  fi
  FILE_CONTENTS[$idx]="${FILE_CONTENTS[$idx]}"$'\n'"$line"
}

add_port_bind() {
  # Usage: add_port_bind "PORT:username"
  PORT_BINDS+=("$1")
}

addcommand() {
  COMMANDS+=("$*")
}

# ---------- User / file / port creation routines ----------

createuser() {
  local i="$1"
  local username="${USER_NAMES[i-1]}"
  local group="${USER_PRIMARY_GROUP[i-1]}"
  local shell="${USER_SHELL[i-1]}"
  local password="${USER_PASSWORD[i-1]}"
  local groups_extra="${USER_GROUPS_EXTRA[i-1]}"
  local lock="${USER_LOCK[i-1]}"

  # Ensure primary group exists if specified
  if [ -n "$group" ]; then
    pct_exec "getent group '$group' >/dev/null 2>&1 || groupadd '$group'"
  fi

  # Choose shell default
  [ -n "$shell" ] || shell="/bin/bash"

  # create user with home and specified options
  if [ -n "$group" ]; then
    pct_exec "useradd -m -s '$shell' -g '$group' '$username' || true"
  else
    pct_exec "useradd -m -s '$shell' '$username' || true"
  fi

  # supplementary groups
  if [ -n "$groups_extra" ]; then
    pct_exec "usermod -aG '$groups_extra' '$username' || true"
  fi

  # Password handling
  if [ -n "$password" ]; then
    if [ "$password" = "!" ]; then
      # nopassword meaning: lock or set unusable password
      pct_exec "usermod -L '$username' || true"
    else
      pct_set_password "${username}:${password}"
    fi
  fi

  if [ "$lock" = "true" ]; then
    pct_exec "usermod -L '$username' || true"
  fi

  # Ensure home ownership
  if [ -n "$group" ]; then
    pct_exec "chown '$username':'$group' '/home/$username' || true"
  else
    pct_exec "chown '$username' '/home/$username' || true"
  fi
}

create_port_bind() {
  local entry="$1"
  local port="${entry%%:*}"
  local username="${entry##*:}"
  if [ -z "$username" ]; then
    echo "Error: Username empty for port $port" >&2
    return 1
  fi
  # install authbind if not present (the container package)
  pct_install_package authbind || true
  pct_exec "mkdir -p /etc/authbind/byport"
  pct_exec "touch /etc/authbind/byport/$port"
  pct_exec "chmod 500 /etc/authbind/byport/$port"
  pct_exec "chown '$username' /etc/authbind/byport/$port"
}

# ---------- Prepare network config string for pct create ----------
build_net_config_string() {
  local out=""
  local idx=0
  for cfg in "${NET_CONFIGS[@]}"; do
    out="${out} --net${idx} ${cfg}"
    idx=$((idx + 1))
  done
  printf '%s' "$out"
}

# ---------- Start of main script operations ----------
vprint "------------------------------ Creation of LXC Container ------------------------------"

# Ensure template is present
if [ ! -f "/var/lib/vz/template/cache/$CT_template_filename" ]; then
  vprint "Downloading template $CT_template_filename ..."
  wget -q --show-progress "$CT_template_download" -O "/var/lib/vz/template/cache/$CT_template_filename"
fi

# Determine os type heuristically from filename
case "$CT_template_filename" in
  *almalinux*|*amazonlinux*|*centos*|*openeuler*|*oracle*|*rockylinux*|*springdalelinux*) CT_os_type="centos" ;;
  *alpine*) CT_os_type="alpine" ;;
  *alt*|*busybox*|*plamo*|*slackware*|*voidlinux*|*openwrt*) CT_os_type="unmanaged" ;;
  *archlinux*) CT_os_type="archlinux" ;;
  *debian*|*devuan*|*kali*) CT_os_type="debian" ;;
  *fedora*) CT_os_type="fedora" ;;
  *funtoo*|*gentoo*) CT_os_type="gentoo" ;;
  *mint*) CT_os_type="ubuntu" ;;
  *nixos*) CT_os_type="nixos" ;;
  *opensuse*) CT_os_type="opensuse" ;;
  *ubuntu*) CT_os_type="ubuntu" ;;
  *) CT_os_type="unmanaged" ;;
esac
vprint "Detected CT_os_type=${CT_os_type}"

# Ensure CT_ID is not in use; increment until free
existing_ids=$(pct list | awk 'NR>1 {print $1}' | sort -n || true)
# default minimum CT_ID
: "${CT_ID:=100}"
CT_ID=$((CT_ID < 100 ? 100 : CT_ID))
while echo "$existing_ids" | grep -qw "$CT_ID"; do
  CT_ID=$((CT_ID + 1))
done
vprint "Using CT_ID=$CT_ID"

# Build network config string (call addnet before create)
# Example you used:
# addnet eth0 hwaddr "DE:AD:BE:EF:99:55" ip dhcp ip6 manual firewall 0 bridge vmbr0
# So ensure user calls addnet before create. If not, NET_CONFIGS will be empty.

# Write temporary public key usage: we will install key in container after start
# Build pct create command
NET_STR=$(build_net_config_string)

vprint "pct create $CT_ID $CT_template_file --arch amd64 --cores $CT_cores --memory $CT_memory --hostname $CT_hostname $NET_STR --rootfs local-lvm:$CT_rootfs_size --features nesting=1 --unprivileged 0 --ostype $CT_os_type"
pct create "$CT_ID" "$CT_template_file" --arch amd64 --cores "$CT_cores" --memory "$CT_memory" --hostname "$CT_hostname" $NET_STR --rootfs "local-lvm:$CT_rootfs_size" --features nesting=1 --unprivileged 0 --ostype "$CT_os_type"

# Start container
pct start "$CT_ID"
# Wait until running
vprint "Waiting for container $CT_ID to run..."
while :; do
  status=$(pct status "$CT_ID" || true)
  case "$status" in
    *running*) break ;;
    *stopped*) sleep 1 ;;
    *) sleep 1 ;;
  esac
done
vprint "Container $CT_ID is running."

# Install public SSH key for root and for a 'deploy' user if needed
if [ -n "$CT_key" ]; then
  # ensure authorized_keys
  pct_exec "mkdir -p /root/.ssh && chmod 700 /root/.ssh"
  # append the key safely
  printf '%s\n' "$CT_key" | pct exec "$CT_ID" -- /bin/sh -c "cat >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
  vprint "SSH key installed for root"
fi

# Set console mode in LXC conf file if desired (modify node path if different)
LXC_CONF_FILE="/etc/pve/nodes/$(hostname)/lxc/$CT_ID.conf"
# If that node path exists, append; otherwise skip silently
if [ -w "$LXC_CONF_FILE" ] || [ -d "$(dirname "$LXC_CONF_FILE")" ]; then
  echo "cmode: shell" >> "$LXC_CONF_FILE" || true
fi

# Enable root login and password auth if requested (operates inside container)
if [ "${CT_enable_root_login}" = "true" ]; then
  pct_exec "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || true"
fi
if [ -n "${CT_root_password}" ]; then
  pct_exec "sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true"
  pct_set_password "root:${CT_root_password}"
  pct_exec "systemctl restart sshd || systemctl restart ssh || true"
fi

# Update package manager and install base packages
pct_update_package_manager || true
if [ -n "${CT_install_packages:-}" ]; then
  pct_install_package $CT_install_packages || true
fi

# ---------- Example of how to populate data based on your original usage ----------
# Add network example (you can keep/change these calls above the create call)
# Recreate the original addnet invocation here to ensure example data:
# addnet eth0 hwaddr "DE:AD:BE:EF:99:55" ip dhcp ip6 manual firewall 0 bridge vmbr0
# If not already set by the user, create it now:
if [ "${#NET_CONFIGS[@]}" -eq 0 ]; then
  addnet eth0 hwaddr "DE:AD:BE:EF:99:55" ip dhcp ip6 manual firewall 0 bridge vmbr0
  # rebuild NET_STR is not used for create (already created), but keep NET_CONFIGS for record
fi

# Example user from your original script: adduser user nopassword nologin lock groups docker
# We'll add that user now if no users added
if [ "${#USER_NAMES[@]}" -eq 0 ]; then
  adduser "user" nopassword nologin lock groups docker
fi

# Example files and lines for vaultwarden docker-compose
if [ "${#FILE_PATHS[@]}" -eq 0 ]; then
  addfile "/opt/vaultwarden/docker-compose.yml" "0644" "root:root" "version: '3.7'
services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: vaultwarden
    environment:
      DOMAIN: 'https://$CT_hostname$CT_network_suffix'
      ROCKET_PORT: 443
      ENABLE_SSL: 'true'
      SIGNUPS_ALLOWED: 'true'
      ROCKET_TLS: '{certs=/certs/fullchain.pem,key=/certs/privkey.pem}'
    volumes:
      - /opt/vaultwarden-data/:/data/
      - /opt/vaultwarden-certs/:/certs/:ro
    ports:
      - 443:443
    restart: unless-stopped"
fi

# Example commands
if [ "${#COMMANDS[@]}" -eq 0 ]; then
  addcommand mkdir -p /opt/vaultwarden/ /opt/vaultwarden-certs/ /opt/vaultwarden-data/
  addcommand "openssl req -x509 -newkey rsa:4096 -keyout /opt/vaultwarden-certs/privkey.pem -out /opt/vaultwarden-certs/fullchain.pem -sha256 -days 36500 -nodes -subj '/CN=${CT_hostname}${CT_network_suffix}'"
  addcommand "sudo -u user docker-compose -f /opt/vaultwarden/docker-compose.yml up -d"
fi

# Example port bind
if [ "${#PORT_BINDS[@]}" -eq 0 ]; then
  add_port_bind "443:user"
fi

# ---------- Provision users ----------
if [ "${#USER_NAMES[@]}" -gt 0 ]; then
  vprint "Creating ${#USER_NAMES[@]} users..."
  for idx in $(seq 1 "${#USER_NAMES[@]}"); do
    createuser "$idx"
  done
fi

# ---------- Write files ----------
if [ "${#FILE_PATHS[@]}" -gt 0 ]; then
  vprint "Writing ${#FILE_PATHS[@]} files into container..."
  for idx in $(seq 1 "${#FILE_PATHS[@]}"); do
    i=$((idx-1))
    dest="${FILE_PATHS[i]}"
    perm="${FILE_PERMS[i]}"
    owner="${FILE_OWNER[i]}"
    content="${FILE_CONTENTS[i]}"
    # overwrite the file (create parent dirs)
    write_into_container_file "$dest" "$content" "overwrite"
    [ -n "$perm" ] && pct_exec "chmod $perm '$dest' || true"
    [ -n "$owner" ] && pct_exec "chown $owner '$dest' || true"
  done
fi

# ---------- Create authbind port files ----------
if [ "${#PORT_BINDS[@]}" -gt 0 ]; then
  vprint "Configuring authbind port files..."
  for entry in "${PORT_BINDS[@]}"; do
    create_port_bind "$entry"
  done
fi

# ---------- Run additional commands ----------
if [ "${#COMMANDS[@]}" -gt 0 ]; then
  vprint "Running ${#COMMANDS[@]} post-provision commands..."
  for cmd in "${COMMANDS[@]}"; do
    pct_exec "$cmd"
  done
fi

vprint "Provisioning finished for container $CT_ID."
