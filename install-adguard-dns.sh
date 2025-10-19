#!/bin/bash

set -e

SCRIPT_VERSION="1.0.0"
LOG_FILE="/var/log/adguard-setup.log"
DOMAIN_FILE="/root/adguard-domain.txt"
ADGUARD_DIR="/opt/AdGuardHome"
ADGUARD_CONF_DIR="/opt/AdGuardHome"
CERT_DIR="/etc/adguard/certs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_logo() {
    cat << "EOF"
    
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     █████╗ ██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗    ║
    ║    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗   ║
    ║    ███████║██║  ██║██║  ███╗██║   ██║███████║██████╔╝   ║
    ║    ██╔══██║██║  ██║██║   ██║██║   ██║██╔══██║██╔══██╗   ║
    ║    ██║  ██║██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║   ║
    ║    ╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ║
    ║                                                           ║
    ║            Secure DNS Resolver Setup Script              ║
    ║                   Version 1.0.0                           ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝

EOF
}

check_root() {
    if [ "$EUID" -ne 0 ]; then 
        error "Script ini harus dijalankan sebagai root. Gunakan: sudo bash $0"
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        error "Tidak dapat mendeteksi OS. Script ini untuk Ubuntu/Debian."
    fi
    
    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        error "OS tidak didukung. Script ini hanya untuk Ubuntu/Debian."
    fi
    
    log "Terdeteksi: $OS $VER"
}

get_server_ip() {
    SERVER_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || curl -s ipinfo.io/ip)
    if [ -z "$SERVER_IP" ]; then
        error "Tidak dapat mendeteksi IP server"
    fi
    log "IP Server: $SERVER_IP"
}

update_system() {
    log "Memperbarui sistem..."
    apt update -y >> "$LOG_FILE" 2>&1
    apt upgrade -y >> "$LOG_FILE" 2>&1
    log "Sistem berhasil diperbarui"
}

install_dependencies() {
    log "Menginstal dependencies..."
    apt install -y curl wget unzip ufw jq openssl ca-certificates >> "$LOG_FILE" 2>&1
    
    if ! command -v certbot &> /dev/null; then
        apt install -y certbot >> "$LOG_FILE" 2>&1
    fi
    
    log "Dependencies berhasil diinstal"
}

setup_duckdns_domain() {
    info "Setup domain dengan DuckDNS..."
    echo ""
    echo -e "${CYAN}Opsi domain:${NC}"
    echo "1. Gunakan DuckDNS (gratis, butuh token dari duckdns.org)"
    echo "2. Gunakan domain sendiri"
    echo "3. Skip domain setup (gunakan IP saja)"
    read -p "Pilih opsi (1/2/3): " domain_choice
    
    case $domain_choice in
        1)
            read -p "Masukkan DuckDNS token Anda: " DUCKDNS_TOKEN
            read -p "Masukkan subdomain yang diinginkan (misal: mydns): " SUBDOMAIN
            
            FULL_DOMAIN="${SUBDOMAIN}.duckdns.org"
            
            RESPONSE=$(curl -s "https://www.duckdns.org/update?domains=${SUBDOMAIN}&token=${DUCKDNS_TOKEN}&ip=${SERVER_IP}")
            
            if [ "$RESPONSE" == "OK" ]; then
                log "Domain DuckDNS berhasil dikonfigurasi: $FULL_DOMAIN"
                echo "$FULL_DOMAIN" > "$DOMAIN_FILE"
            else
                error "Gagal mengkonfigurasi DuckDNS. Periksa token dan subdomain Anda."
            fi
            ;;
        2)
            read -p "Masukkan domain Anda (misal: dns.example.com): " CUSTOM_DOMAIN
            echo "$CUSTOM_DOMAIN" > "$DOMAIN_FILE"
            warn "Pastikan DNS record untuk $CUSTOM_DOMAIN sudah mengarah ke $SERVER_IP"
            read -p "Tekan Enter untuk melanjutkan setelah DNS dikonfigurasi..."
            ;;
        3)
            echo "$SERVER_IP" > "$DOMAIN_FILE"
            warn "Menggunakan IP address. SSL certificate akan self-signed."
            ;;
        *)
            error "Pilihan tidak valid"
            ;;
    esac
    
    DOMAIN=$(cat "$DOMAIN_FILE")
    log "Domain/IP yang digunakan: $DOMAIN"
}

install_adguard() {
    log "Mengunduh dan menginstal AdGuard Home..."
    
    cd /tmp
    wget -q --show-progress https://static.adguard.com/adguardhome/release/AdGuardHome_linux_amd64.tar.gz || error "Gagal mengunduh AdGuard Home"
    
    tar -xzf AdGuardHome_linux_amd64.tar.gz || error "Gagal ekstrak AdGuard Home"
    
    if [ -d "$ADGUARD_DIR" ]; then
        warn "AdGuard Home sudah terinstal. Membuat backup..."
        systemctl stop AdGuardHome 2>/dev/null || true
        mv "$ADGUARD_DIR" "${ADGUARD_DIR}.backup.$(date +%s)"
    fi
    
    mv AdGuardHome "$ADGUARD_DIR"
    
    log "AdGuard Home berhasil diinstal"
}

create_systemd_service() {
    log "Membuat systemd service untuk AdGuard Home..."
    
    cat > /etc/systemd/system/AdGuardHome.service << 'EOF'
[Unit]
Description=AdGuard Home: Network-level blocker
After=network.target
After=syslog.target

[Service]
Type=simple
WorkingDirectory=/opt/AdGuardHome
ExecStart=/opt/AdGuardHome/AdGuardHome --no-check-update -c /opt/AdGuardHome/AdGuardHome.yaml -w /opt/AdGuardHome
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "Systemd service berhasil dibuat"
}

setup_ssl_certificate() {
    log "Setup SSL certificate..."
    
    DOMAIN=$(cat "$DOMAIN_FILE")
    
    mkdir -p "$CERT_DIR"
    
    if [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        warn "Menggunakan IP address, membuat self-signed certificate..."
        create_selfsigned_cert
        return
    fi
    
    systemctl stop AdGuardHome 2>/dev/null || true
    
    info "Mencoba mendapatkan Let's Encrypt certificate..."
    if certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --preferred-challenges http >> "$LOG_FILE" 2>&1; then
        log "Let's Encrypt certificate berhasil didapatkan"
        USE_LETSENCRYPT=true
        CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    else
        warn "Gagal mendapatkan Let's Encrypt certificate, menggunakan self-signed..."
        create_selfsigned_cert
    fi
}

create_selfsigned_cert() {
    DOMAIN=$(cat "$DOMAIN_FILE")
    
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout "$CERT_DIR/privkey.pem" \
        -out "$CERT_DIR/fullchain.pem" \
        -days 365 \
        -subj "/CN=$DOMAIN" >> "$LOG_FILE" 2>&1
    
    USE_LETSENCRYPT=false
    CERT_PATH="$CERT_DIR/fullchain.pem"
    KEY_PATH="$CERT_DIR/privkey.pem"
    
    log "Self-signed certificate berhasil dibuat"
}

configure_adguard() {
    log "Mengkonfigurasi AdGuard Home..."
    
    DOMAIN=$(cat "$DOMAIN_FILE")
    
    systemctl stop AdGuardHome 2>/dev/null || true
    
    cat > "${ADGUARD_CONF_DIR}/AdGuardHome.yaml" << EOF
bind_host: 0.0.0.0
bind_port: 3000
users: []
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: ""
theme: auto
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  anonymize_client_ip: false
  ratelimit: 20
  ratelimit_subnet_len_ipv4: 24
  ratelimit_subnet_len_ipv6: 56
  ratelimit_whitelist: []
  refuse_any: true
  upstream_dns:
    - https://dns10.quad9.net/dns-query
    - https://dns.cloudflare.com/dns-query
    - https://dns.google/dns-query
  upstream_dns_file: ""
  bootstrap_dns:
    - 9.9.9.10
    - 149.112.112.10
    - 2620:fe::10
  fallback_dns: []
  all_servers: false
  fastest_addr: false
  fastest_timeout: 1s
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind
  trusted_proxies:
    - 127.0.0.0/8
    - ::1/128
  cache_size: 4194304
  cache_ttl_min: 0
  cache_ttl_max: 0
  cache_optimistic: false
  bogus_nxdomain: []
  aaaa_disabled: false
  enable_dnssec: false
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
  ipset: []
  ipset_file: ""
  bootstrap_prefer_ipv6: false
  upstream_timeout: 10s
  private_networks: []
  use_private_ptr_resolvers: true
  local_ptr_upstreams: []
  use_dns64: false
  dns64_prefixes: []
  serve_http3: false
  use_http3_upstreams: false
tls:
  enabled: true
  server_name: ${DOMAIN}
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  port_dnscrypt: 0
  dnscrypt_config_file: ""
  allow_unencrypted_doh: false
  certificate_chain: ${CERT_PATH}
  private_key: ${KEY_PATH}
  certificate_path: ""
  private_key_path: ""
  strict_sni_check: false
querylog:
  ignored: []
  interval: 2160h
  size_memory: 1000
  enabled: true
  file_enabled: true
statistics:
  ignored: []
  interval: 24h
  enabled: true
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt
    name: AdAway Default Blocklist
    id: 2
whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
  interface_name: ""
  local_domain_name: lan
  dhcpv4:
    gateway_ip: ""
    subnet_mask: ""
    range_start: ""
    range_end: ""
    lease_duration: 86400
    icmp_timeout_msec: 1000
    options: []
  dhcpv6:
    range_start: ""
    lease_duration: 86400
    ra_slaac_only: false
    ra_allow_slaac: false
clients:
  runtime_sources:
    whois: true
    arp: true
    rdns: true
    dhcp: true
    hosts: true
  persistent: []
log:
  file: ""
  max_backups: 0
  max_size: 100
  max_age: 3
  compress: false
  local_time: false
  verbose: false
os:
  group: ""
  user: ""
  rlimit_nofile: 0
schema_version: 27
EOF

    log "Konfigurasi AdGuard Home selesai"
    info "Username default: admin"
    info "Password default akan diset saat pertama kali akses web interface"
}

setup_firewall() {
    log "Mengkonfigurasi firewall..."
    
    ufw --force enable >> "$LOG_FILE" 2>&1
    
    ufw allow 22/tcp >> "$LOG_FILE" 2>&1
    ufw allow 53/tcp >> "$LOG_FILE" 2>&1
    ufw allow 53/udp >> "$LOG_FILE" 2>&1
    ufw allow 80/tcp >> "$LOG_FILE" 2>&1
    ufw allow 443/tcp >> "$LOG_FILE" 2>&1
    ufw allow 443/udp >> "$LOG_FILE" 2>&1
    ufw allow 853/tcp >> "$LOG_FILE" 2>&1
    ufw allow 853/udp >> "$LOG_FILE" 2>&1
    ufw allow 3000/tcp >> "$LOG_FILE" 2>&1
    
    ufw --force reload >> "$LOG_FILE" 2>&1
    
    log "Firewall berhasil dikonfigurasi"
}

start_adguard() {
    log "Memulai AdGuard Home..."
    
    systemctl daemon-reload
    systemctl enable AdGuardHome >> "$LOG_FILE" 2>&1
    systemctl restart AdGuardHome >> "$LOG_FILE" 2>&1
    
    sleep 3
    
    if systemctl is-active --quiet AdGuardHome; then
        log "AdGuard Home berhasil dijalankan"
    else
        error "Gagal menjalankan AdGuard Home. Periksa log: journalctl -u AdGuardHome -n 50"
    fi
}

print_success() {
    DOMAIN=$(cat "$DOMAIN_FILE")
    
    clear
    print_logo
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                ║${NC}"
    echo -e "${GREEN}║           ✅  INSTALASI BERHASIL DISELESAIKAN!  ✅            ║${NC}"
    echo -e "${GREEN}║                                                                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}📡 Informasi DNS Server:${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BLUE}🌐 Domain/IP:${NC}        $DOMAIN"
    echo -e "  ${BLUE}🖥️  Server IP:${NC}       $SERVER_IP"
    echo ""
    echo -e "${CYAN}🔒 Akses DNS Aman (Encrypted):${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} DNS-over-HTTPS (DoH):"
    echo -e "    https://${DOMAIN}/dns-query"
    echo ""
    echo -e "  ${GREEN}✓${NC} DNS-over-TLS (DoT):"
    echo -e "    ${DOMAIN}"
    echo ""
    echo -e "  ${GREEN}✓${NC} DNS-over-QUIC (DoQ):"
    echo -e "    quic://${DOMAIN}"
    echo ""
    echo -e "${CYAN}⚙️  Panel Admin:${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BLUE}🔗 URL:${NC}              http://${SERVER_IP}:3000"
    echo -e "  ${BLUE}👤 Setup:${NC}            Buat username dan password saat pertama akses"
    echo ""
    echo -e "${CYAN}📝 DNS Tradisional (Unencrypted):${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BLUE}Primary DNS:${NC}         ${SERVER_IP}"
    echo -e "  ${BLUE}Port:${NC}                53"
    echo ""
    
    if [ "$USE_LETSENCRYPT" = true ]; then
        echo -e "${CYAN}🔐 SSL Certificate:${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "  ${GREEN}✓${NC} Let's Encrypt (Valid)"
        echo -e "  ${BLUE}Auto-renewal:${NC}    Enabled"
        echo ""
    else
        echo -e "${CYAN}🔐 SSL Certificate:${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "  ${YELLOW}⚠${NC}  Self-Signed Certificate"
        echo -e "  ${BLUE}Note:${NC}            Browser akan menampilkan warning (normal)"
        echo ""
    fi
    
    echo -e "${CYAN}📚 Cara Menggunakan:${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  1. Buka panel admin di http://${SERVER_IP}:3000"
    echo -e "  2. Ikuti wizard setup untuk membuat username dan password admin"
    echo -e "  3. DoH/DoT sudah dikonfigurasi otomatis dengan SSL certificate"
    echo -e "  4. Konfigurasi DNS di perangkat Anda:"
    echo ""
    echo -e "     ${BLUE}Di Android/iOS:${NC}"
    echo -e "     - Gunakan Private DNS: ${DOMAIN}"
    echo ""
    echo -e "     ${BLUE}Di Browser (Chrome/Firefox):${NC}"
    echo -e "     - Aktifkan DNS-over-HTTPS"
    echo -e "     - URL: https://${DOMAIN}/dns-query"
    echo ""
    echo -e "     ${BLUE}Di Router/Sistem:${NC}"
    echo -e "     - Set DNS Server: ${SERVER_IP}"
    echo ""
    echo -e "${CYAN}🔧 Perintah Berguna:${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BLUE}Status service:${NC}      systemctl status AdGuardHome"
    echo -e "  ${BLUE}Restart service:${NC}     systemctl restart AdGuardHome"
    echo -e "  ${BLUE}View logs:${NC}           journalctl -u AdGuardHome -f"
    echo -e "  ${BLUE}Stop service:${NC}        systemctl stop AdGuardHome"
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}Log instalasi tersimpan di:${NC} $LOG_FILE"
    echo ""
}

main() {
    print_logo
    echo ""
    
    check_root
    detect_os
    get_server_ip
    
    echo ""
    read -p "Lanjutkan instalasi? (y/n): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo "Instalasi dibatalkan."
        exit 0
    fi
    
    update_system
    install_dependencies
    setup_duckdns_domain
    install_adguard
    create_systemd_service
    setup_ssl_certificate
    configure_adguard
    setup_firewall
    start_adguard
    print_success
}

main "$@"
