# DNS Audit Tool - Bash Version (macOS / Linux)

A Bash script that performs a comprehensive DNS audit on any domain. It checks over 30 DNS record types, identifies the DNS hosting provider via live WHOIS lookup, and exports the results to both a timestamped TXT file and a CSV file.

No installations required — uses tools built into macOS and Linux.

---

## Quick Run

Run directly from Terminal with no download needed:

```bash
bash <(curl -s "https://raw.githubusercontent.com/motionbourne/powershell_scripts/main/audit_dns.sh")
```

You will be prompted to enter the domain you want to audit.

---

## Download and Run

If you prefer to save the script locally:

```bash
curl -o ~/audit_dns.sh "https://raw.githubusercontent.com/motionbourne/powershell_scripts/main/audit_dns.sh"
chmod +x ~/audit_dns.sh
~/audit_dns.sh
```

---

## What It Checks

### Main Domain
| Record | Description |
|--------|-------------|
| A | IPv4 address |
| AAAA | IPv6 address |
| MX | Mail server routing |
| TXT | SPF and other text records |
| NS | Nameservers |
| SOA | Start of Authority |
| CAA | SSL certificate authority permissions |

### Web & Server Records
| Record | Description |
|--------|-------------|
| WWW | Website CNAME or A record |
| FTP | FTP server |
| VPN | VPN endpoint |
| Mail | Legacy mail server |
| SMTP | SMTP server |
| IMAP | IMAP server |
| POP | POP3 server |

### Email Security
| Record | Description |
|--------|-------------|
| DMARC | Domain-based message authentication policy |
| DKIM General | General DKIM key record |
| DKIM Mailchimp (k3) | Mailchimp DKIM signing record |
| DKIM Microsoft Selector1 | Microsoft 365 DKIM selector 1 |
| DKIM Microsoft Selector2 | Microsoft 365 DKIM selector 2 |
| DKIM Google Workspace | Google Workspace DKIM signing record |
| MTA-STS | Mail transport security policy |
| TLS Reporting | TLS failure reporting record |

### Microsoft 365
| Record | Description |
|--------|-------------|
| Autodiscover | Outlook autodiscover CNAME |
| Microsoft Online ID | Microsoft identity record |
| Enterprise Registration | Device registration for M365 |
| Enterprise Enrollment | MDM device enrollment |
| Lync Discover | Teams / Skype for Business |
| SIP | SIP address for Teams Voice |
| SIP TLS | SIP TLS service record |
| SIP Federation | Teams federation SRV record |

---

## DNS Provider Detection

The script automatically identifies who is hosting the DNS by performing a live RDAP (WHOIS) lookup on the nameserver domain.

Example output:
```
==============================
 DNS PROVIDER
==============================
 Nameserver Root Domain : one.com
 Provider/Registrant    : One.com A/S
 Nameservers            : ns1.one.com ns2.one.com
```

---

## Output Files

Every audit automatically saves two files to ~/tools/:

| File | Description |
|------|-------------|
| DNS_Audit_domain.com_2026-02-19_13-45-22.txt | Full plain text transcript of the audit |
| DNS_Audit_domain.com_2026-02-19_13-45-22.csv | CSV export — opens in Excel or Numbers |

The ~/tools/ folder is created automatically if it does not exist.

---

## Requirements

- macOS or Linux
- bash (built in)
- dig (built into macOS and most Linux distributions)
- curl (built into macOS and most Linux distributions)

No additional software or package managers required.

---

## Notes

- Each audit creates a new timestamped file so previous reports are never overwritten
- If a DNS record is not found it will display clearly as Not Found
- The CSV file opens natively in Microsoft Excel or Apple Numbers
- The script works for any domain worldwide — just enter the domain when prompted
- For Windows users, see the PowerShell version Audit_DNS.ps1 in this repository
