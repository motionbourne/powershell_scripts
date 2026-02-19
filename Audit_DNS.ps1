$domain = Read-Host "Enter domain to audit"

function Get-DNSProvider {
    param($domain)
    try {
        $nsRecords = Resolve-DnsName $domain -Type NS -ErrorAction Stop | Where-Object { $_.QueryType -eq "NS" }
        if ($nsRecords) {
            $firstNS = $nsRecords[0].NameHost.ToLower()

            # Extract the root domain from the nameserver (e.g. ns1.one.com -> one.com)
            $nsParts = $firstNS.Split(".")
            if ($nsParts.Count -ge 2) {
                $nsRootDomain = "$($nsParts[$nsParts.Count - 2]).$($nsParts[$nsParts.Count - 1])"
            } else {
                $nsRootDomain = $firstNS
            }

            # Query WHOIS via rdap (public REST API - no install needed)
            $providerName = "Unknown"
            try {
                $rdapUrl = "https://rdap.org/domain/$nsRootDomain"
                $rdapResponse = Invoke-RestMethod -Uri $rdapUrl -TimeoutSec 5 -ErrorAction Stop

                # Try to get the registrant org or name
                if ($rdapResponse.entities) {
                    foreach ($entity in $rdapResponse.entities) {
                        if ($entity.roles -contains "registrant" -or $entity.roles -contains "registrar") {
                            if ($entity.vcardArray) {
                                foreach ($vcard in $entity.vcardArray[1]) {
                                    if ($vcard[0] -eq "org" -or $vcard[0] -eq "fn") {
                                        $providerName = $vcard[3]
                                        break
                                    }
                                }
                            }
                            if ($providerName -ne "Unknown") { break }
                        }
                    }
                }

                # Fallback to registrar name if registrant not found
                if ($providerName -eq "Unknown" -and $rdapResponse.entities) {
                    foreach ($entity in $rdapResponse.entities) {
                        if ($entity.vcardArray) {
                            foreach ($vcard in $entity.vcardArray[1]) {
                                if ($vcard[0] -eq "fn") {
                                    $providerName = $vcard[3]
                                    break
                                }
                            }
                        }
                        if ($providerName -ne "Unknown") { break }
                    }
                }
            } catch {
                $providerName = "Could not retrieve (WHOIS lookup failed)"
            }

            Write-Host "`n============================================" -ForegroundColor Cyan
            Write-Host " DNS PROVIDER" -ForegroundColor Cyan
            Write-Host "============================================" -ForegroundColor Cyan
            Write-Host " Nameserver Root Domain : $nsRootDomain" -ForegroundColor Cyan
            Write-Host " Provider/Registrant    : $providerName" -ForegroundColor Cyan
            Write-Host " Nameservers:" -ForegroundColor Cyan
            $nsRecords | ForEach-Object { Write-Host "   - $($_.NameHost)" -ForegroundColor Cyan }
            Write-Host "============================================" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "Could not determine DNS provider" -ForegroundColor Yellow
    }
}

function Check-DNS {
    param($hostname, $type)
    try {
        $result = Resolve-DnsName $hostname -Type $type -ErrorAction Stop
        $filtered = $result | Where-Object { $_.QueryType -ne "SOA" -and $_.QueryType -ne "NS" }
        if ($filtered) {
            $filtered
        } else {
            Write-Host "No $type record found for $hostname" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "No $type record found for $hostname" -ForegroundColor Yellow
    }
}

$sections = @(
    @{ Name = "Main Domain - A Record";                  Hostname = $domain;                                  Type = "A"     }
    @{ Name = "Main Domain - AAAA (IPv6)";               Hostname = $domain;                                  Type = "AAAA"  }
    @{ Name = "Main Domain - MX (Mail)";                 Hostname = $domain;                                  Type = "MX"    }
    @{ Name = "Main Domain - TXT (SPF etc)";             Hostname = $domain;                                  Type = "TXT"   }
    @{ Name = "Main Domain - NS (Nameservers)";          Hostname = $domain;                                  Type = "NS"    }
    @{ Name = "Main Domain - SOA";                       Hostname = $domain;                                  Type = "SOA"   }
    @{ Name = "Main Domain - CAA (SSL Certificate)";     Hostname = $domain;                                  Type = "CAA"   }
    @{ Name = "WWW Record";                              Hostname = "www.$domain";                            Type = "CNAME" }
    @{ Name = "FTP Record";                              Hostname = "ftp.$domain";                            Type = "A"     }
    @{ Name = "VPN Record";                              Hostname = "vpn.$domain";                            Type = "A"     }
    @{ Name = "Mail Record";                             Hostname = "mail.$domain";                           Type = "A"     }
    @{ Name = "SMTP Record";                             Hostname = "smtp.$domain";                           Type = "A"     }
    @{ Name = "IMAP Record";                             Hostname = "imap.$domain";                           Type = "A"     }
    @{ Name = "POP Record";                              Hostname = "pop.$domain";                            Type = "A"     }
    @{ Name = "DMARC";                                   Hostname = "_dmarc.$domain";                         Type = "TXT"   }
    @{ Name = "DKIM - General";                          Hostname = "_domainkey.$domain";                     Type = "TXT"   }
    @{ Name = "DKIM - Mailchimp (k3)";                   Hostname = "k3._domainkey.$domain";                  Type = "CNAME" }
    @{ Name = "DKIM - Microsoft Selector1";              Hostname = "selector1._domainkey.$domain";           Type = "CNAME" }
    @{ Name = "DKIM - Microsoft Selector2";              Hostname = "selector2._domainkey.$domain";           Type = "CNAME" }
    @{ Name = "DKIM - Google Workspace";                 Hostname = "google._domainkey.$domain";              Type = "TXT"   }
    @{ Name = "MTA-STS (Email Transport Security)";      Hostname = "_mta-sts.$domain";                       Type = "TXT"   }
    @{ Name = "TLS Reporting";                           Hostname = "_smtp._tls.$domain";                     Type = "TXT"   }
    @{ Name = "Autodiscover (Microsoft 365)";            Hostname = "autodiscover.$domain";                   Type = "CNAME" }
    @{ Name = "Microsoft Online ID";                     Hostname = "msoid.$domain";                          Type = "CNAME" }
    @{ Name = "Enterprise Registration (M365)";          Hostname = "enterpriseregistration.$domain";         Type = "CNAME" }
    @{ Name = "Enterprise Enrollment (MDM)";             Hostname = "enterpriseenrollment.$domain";           Type = "CNAME" }
    @{ Name = "Lync Discover (Teams/SfB)";               Hostname = "lyncdiscover.$domain";                   Type = "CNAME" }
    @{ Name = "SIP Record (Teams Voice)";                Hostname = "sip.$domain";                            Type = "CNAME" }
    @{ Name = "SIP TLS (Teams Voice)";                   Hostname = "_sip._tls.$domain";                      Type = "SRV"   }
    @{ Name = "SIP Federation (Teams)";                  Hostname = "_sipfederationtls._tcp.$domain";         Type = "SRV"   }
)

Write-Host "`n============================================" -ForegroundColor Magenta
Write-Host "   DNS AUDIT REPORT FOR: $($domain.ToUpper())" -ForegroundColor Magenta
Write-Host "   $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor Magenta
Write-Host "============================================" -ForegroundColor Magenta

# Detect and display DNS provider at the top
Get-DNSProvider -domain $domain

foreach ($section in $sections) {
    Write-Host "`n==============================" -ForegroundColor Green
    Write-Host " $($section.Name)" -ForegroundColor Green
    Write-Host "==============================" -ForegroundColor Green
    Check-DNS -hostname $section.Hostname -type $section.Type
}

Write-Host "`n============================================" -ForegroundColor Magenta
Write-Host "   AUDIT COMPLETE" -ForegroundColor Magenta
Write-Host "============================================`n" -ForegroundColor Magenta
