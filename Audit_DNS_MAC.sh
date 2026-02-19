#!/bin/bash

# ============================================
# DNS Audit Tool - Bash Version (macOS/Linux)
# ============================================

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Colour

# Output folder
OUTPUT_FOLDER="$HOME/tools"
mkdir -p "$OUTPUT_FOLDER"

# Prompt for domain
read -p "Enter domain to audit: " DOMAIN
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_TXT="$OUTPUT_FOLDER/DNS_Audit_${DOMAIN}_${TIMESTAMP}.txt"
OUTPUT_CSV="$OUTPUT_FOLDER/DNS_Audit_${DOMAIN}_${TIMESTAMP}.csv"

# Start logging
exec > >(tee -a "$OUTPUT_TXT") 2>&1

# CSV Header
echo "Section,Record,Hostname,Value,Status" > "$OUTPUT_CSV"

# ---- Functions ----

add_csv() {
    local section="$1"
    local record="$2"
    local hostname="$3"
    local value="$4"
    local status="$5"
    echo "\"$section\",\"$record\",\"$hostname\",\"$value\",\"$status\"" >> "$OUTPUT_CSV"
}

section_header() {
    echo ""
    echo -e "${GREEN}==============================${NC}"
    echo -e "${GREEN} $1${NC}"
    echo -e "${GREEN}==============================${NC}"
}

check_dns() {
    local section="$1"
    local type="$2"
    local hostname="$3"

    section_header "$section"
    result=$(dig +short "$type" "$hostname" 2>/dev/null)

    if [ -n "$result" ]; then
        echo "$result"
        add_csv "$section" "$type" "$hostname" "$result" "FOUND"
    else
        echo -e "${YELLOW}No $type record found for $hostname${NC}"
        add_csv "$section" "$type" "$hostname" "Not Found" "NOT FOUND"
    fi
}

get_dns_provider() {
    section_header "DNS PROVIDER"

    NS_RECORDS=$(dig +short NS "$DOMAIN" 2>/dev/null)
    if [ -z "$NS_RECORDS" ]; then
        echo -e "${YELLOW}Could not determine DNS provider${NC}"
        return
    fi

    FIRST_NS=$(echo "$NS_RECORDS" | head -1 | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')
    NS_ROOT=$(echo "$FIRST_NS" | awk -F'.' '{print $(NF-1)"."$NF}')

    echo -e "${CYAN} Nameserver Root Domain : $NS_ROOT${NC}"
    echo -e "${CYAN} Nameservers            : $(echo $NS_RECORDS | tr '\n' ' ')${NC}"

    # RDAP lookup for provider name
    PROVIDER="Unknown"
    RDAP_RESPONSE=$(curl -s --max-time 5 "https://rdap.org/domain/$NS_ROOT" 2>/dev/null)

    if [ -n "$RDAP_RESPONSE" ]; then
        PROVIDER=$(echo "$RDAP_RESPONSE" | grep -o '"fn"[^]]*' | head -1 | grep -o '"[^"]*"$' | tr -d '"' 2>/dev/null)
        if [ -z "$PROVIDER" ]; then
            PROVIDER="Unknown"
        fi
    fi

    echo -e "${CYAN} Provider/Registrant    : $PROVIDER${NC}"
    add_csv "DNS Provider" "NS" "$NS_ROOT" "$(echo $NS_RECORDS | tr '\n' ' ')" "INFO"
}

# ---- Header ----
echo ""
echo -e "${MAGENTA}============================================${NC}"
echo -e "${MAGENTA}   DNS AUDIT REPORT FOR: $(echo $DOMAIN | tr '[:lower:]' '[:upper:]')${NC}"
echo -e "${MAGENTA}   $(date '+%d/%m/%Y %H:%M:%S')${NC}"
echo -e "${MAGENTA}   Running on: $(uname -s)${NC}"
echo -e "${MAGENTA}============================================${NC}"

# ---- DNS Provider ----
get_dns_provider

# ---- Main Domain ----
check_dns "Main Domain - A Record"           "A"     "$DOMAIN"
check_dns "Main Domain - AAAA (IPv6)"        "AAAA"  "$DOMAIN"
check_dns "Main Domain - MX (Mail)"          "MX"    "$DOMAIN"
check_dns "Main Domain - TXT (SPF etc)"      "TXT"   "$DOMAIN"
check_dns "Main Domain - NS (Nameservers)"   "NS"    "$DOMAIN"
check_dns "Main Domain - SOA"                "SOA"   "$DOMAIN"
check_dns "Main Domain - CAA (SSL Cert)"     "CAA"   "$DOMAIN"

# ---- Web & Server Records ----
check_dns "WWW Record"   "CNAME" "www.$DOMAIN"
check_dns "FTP Record"   "A"     "ftp.$DOMAIN"
check_dns "VPN Record"   "A"     "vpn.$DOMAIN"
check_dns "Mail Record"  "A"     "mail.$DOMAIN"
check_dns "SMTP Record"  "A"     "smtp.$DOMAIN"
check_dns "IMAP Record"  "A"     "imap.$DOMAIN"
check_dns "POP Record"   "A"     "pop.$DOMAIN"

# ---- Email Security ----
check_dns "DMARC"                        "TXT"   "_dmarc.$DOMAIN"
check_dns "DKIM - General"               "TXT"   "_domainkey.$DOMAIN"
check_dns "DKIM - Mailchimp (k3)"        "CNAME" "k3._domainkey.$DOMAIN"
check_dns "DKIM - Microsoft Selector1"   "CNAME" "selector1._domainkey.$DOMAIN"
check_dns "DKIM - Microsoft Selector2"   "CNAME" "selector2._domainkey.$DOMAIN"
check_dns "DKIM - Google Workspace"      "TXT"   "google._domainkey.$DOMAIN"
check_dns "MTA-STS"                      "TXT"   "_mta-sts.$DOMAIN"
check_dns "TLS Reporting"                "TXT"   "_smtp._tls.$DOMAIN"

# ---- Microsoft 365 ----
check_dns "Autodiscover (Microsoft 365)"      "CNAME" "autodiscover.$DOMAIN"
check_dns "Microsoft Online ID"               "CNAME" "msoid.$DOMAIN"
check_dns "Enterprise Registration (M365)"    "CNAME" "enterpriseregistration.$DOMAIN"
check_dns "Enterprise Enrollment (MDM)"       "CNAME" "enterpriseenrollment.$DOMAIN"
check_dns "Lync Discover (Teams/SfB)"         "CNAME" "lyncdiscover.$DOMAIN"
check_dns "SIP Record (Teams Voice)"          "CNAME" "sip.$DOMAIN"
check_dns "SIP TLS (Teams Voice)"             "SRV"   "_sip._tls.$DOMAIN"
check_dns "SIP Federation (Teams)"            "SRV"   "_sipfederationtls._tcp.$DOMAIN"

# ---- Footer ----
echo ""
echo -e "${MAGENTA}============================================${NC}"
echo -e "${MAGENTA}   AUDIT COMPLETE${NC}"
echo -e "${MAGENTA}============================================${NC}"
echo ""
echo -e "${MAGENTA}TXT Report saved to : $OUTPUT_TXT${NC}"
echo -e "${MAGENTA}CSV Report saved to : $OUTPUT_CSV${NC}"
