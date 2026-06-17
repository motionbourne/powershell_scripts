# DNS Audit Tool

A PowerShell script that performs a comprehensive DNS audit on any domain. It checks over 30 DNS record types, identifies the DNS hosting provider via live WHOIS lookup, and exports the results to both a timestamped TXT file and a colour coded Excel spreadsheet.

---

## Quick Run

No installation needed. Run directly from PowerShell:

```powershell
irm "https://raw.githubusercontent.com/motionbourne/powershell_scripts/main/Audit_DNS.ps1" | iex
```

You will be prompted to enter the domain you want to audit.

> **Security note:** this downloads and runs a script straight from the internet. Review it
> first, or pin to a specific commit (replace `main` with a commit hash) to run a fixed,
> audited version.

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

The script automatically identifies who is hosting the DNS by performing a live **RDAP (WHOIS) lookup** on the nameserver domain. This works for any provider — no hardcoded list required.

Example output:
```
============================================
 DNS PROVIDER
============================================
 Nameserver Root Domain : one.com
 Provider/Registrant    : One.com A/S
 Nameservers            : ns1.one.com, ns2.one.com
============================================
```

---

## Output Files

Every audit automatically saves two files to `C:\tools\`:

| File | Description |
|------|-------------|
| `DNS_Audit_domain.com_2026-02-19_13-45-22.txt` | Full plain text transcript of the audit |
| `DNS_Audit_domain.com_2026-02-19_13-45-22.xlsx` | Colour coded Excel spreadsheet |

The `C:\tools\` folder is created automatically if it doesn't exist.

---

## Excel Colour Coding

| Colour | Meaning |
|--------|---------|
| Green | Record found |
| Red | Record not found |
| Blue | Informational (DNS provider) |

The spreadsheet includes a title header with the domain name, audit date, and detected DNS provider. Column headers are on row 4 with filtering and freeze panes enabled.

---

## Requirements

- **Windows PowerShell 5.1** or **PowerShell 7+**
- **Internet access** (for DNS lookups and RDAP provider detection)
- **ImportExcel module** — installed automatically on first run (no Microsoft Office required)

---

## Execution Policy

If you receive an execution policy error, run this once in PowerShell:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

---

## Notes

- Each audit creates a new timestamped file so previous reports are never overwritten
- If a DNS record is not found, it will display clearly as **Not Found** rather than showing a confusing SOA fallback
- The script works for any domain worldwide — just enter the domain when prompted
