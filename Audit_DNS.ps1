$domain = Read-Host "Enter domain to audit"

# Output file setup
$outputFolder = "C:\tools"
if (-not (Test-Path $outputFolder)) { New-Item -ItemType Directory -Path $outputFolder | Out-Null }
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputTxt  = "$outputFolder\DNS_Audit_${domain}_${timestamp}.txt"
$outputXlsx = "$outputFolder\DNS_Audit_${domain}_${timestamp}.xlsx"
Start-Transcript -Path $outputTxt | Out-Null

# Install ImportExcel module if not already installed
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host "Installing ImportExcel module..." -ForegroundColor Yellow
    Install-Module -Name ImportExcel -Scope CurrentUser -Force -ErrorAction Stop
}
Import-Module ImportExcel

# Global results collection for Excel export
$excelResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$providerInfo = ""

function Get-DNSProvider {
    param($domain)
    try {
        $nsRecords = Resolve-DnsName $domain -Type NS -ErrorAction Stop | Where-Object { $_.QueryType -eq "NS" }
        if ($nsRecords) {
            $firstNS = $nsRecords[0].NameHost.ToLower()
            $nsParts = $firstNS.Split(".")
            if ($nsParts.Count -ge 2) {
                $nsRootDomain = "$($nsParts[$nsParts.Count - 2]).$($nsParts[$nsParts.Count - 1])"
            } else {
                $nsRootDomain = $firstNS
            }

            $providerName = "Unknown"
            try {
                $rdapUrl = "https://rdap.org/domain/$nsRootDomain"
                $rdapResponse = Invoke-RestMethod -Uri $rdapUrl -TimeoutSec 5 -ErrorAction Stop
                if ($rdapResponse.entities) {
                    foreach ($entity in $rdapResponse.entities) {
                        if ($entity.roles -contains "registrant" -or $entity.roles -contains "registrar") {
                            if ($entity.vcardArray) {
                                foreach ($vcard in $entity.vcardArray[1]) {
                                    if ($vcard[0] -eq "org" -or $vcard[0] -eq "fn") {
                                        $providerName = $vcard[3]; break
                                    }
                                }
                            }
                            if ($providerName -ne "Unknown") { break }
                        }
                    }
                }
                if ($providerName -eq "Unknown" -and $rdapResponse.entities) {
                    foreach ($entity in $rdapResponse.entities) {
                        if ($entity.vcardArray) {
                            foreach ($vcard in $entity.vcardArray[1]) {
                                if ($vcard[0] -eq "fn") { $providerName = $vcard[3]; break }
                            }
                        }
                        if ($providerName -ne "Unknown") { break }
                    }
                }
            } catch {
                $providerName = "Could not retrieve (WHOIS lookup failed)"
            }

            $script:providerInfo = "$providerName ($nsRootDomain)"
            $nsList = ($nsRecords | ForEach-Object { $_.NameHost }) -join ", "

            Write-Host "`n============================================" -ForegroundColor Cyan
            Write-Host " DNS PROVIDER" -ForegroundColor Cyan
            Write-Host "============================================" -ForegroundColor Cyan
            Write-Host " Nameserver Root Domain : $nsRootDomain" -ForegroundColor Cyan
            Write-Host " Provider/Registrant    : $providerName" -ForegroundColor Cyan
            Write-Host " Nameservers            : $nsList" -ForegroundColor Cyan
            Write-Host "============================================" -ForegroundColor Cyan

            # Add to Excel results
            $script:excelResults.Add([PSCustomObject]@{
                Section  = "DNS Provider"
                Record   = "Nameservers"
                Hostname = $nsRootDomain
                Value    = $nsList
                Status   = "INFO"
                Provider = $providerName
            })
        }
    } catch {
        Write-Host "Could not determine DNS provider" -ForegroundColor Yellow
    }
}

function Check-DNS {
    param($hostname, $type, $sectionName)
    try {
        $result = Resolve-DnsName $hostname -Type $type -ErrorAction Stop
        $filtered = $result | Where-Object { $_.QueryType -ne "SOA" -and $_.QueryType -ne "NS" }
        if ($filtered) {
            $filtered
            foreach ($record in $filtered) {
                $value = if ($record.NameHost) { $record.NameHost }
                         elseif ($record.Strings) { $record.Strings -join " " }
                         elseif ($record.IPAddress) { $record.IPAddress }
                         else { $record | Out-String }
                $script:excelResults.Add([PSCustomObject]@{
                    Section  = $sectionName
                    Record   = $type
                    Hostname = $hostname
                    Value    = $value
                    Status   = "FOUND"
                    Provider = ""
                })
            }
        } else {
            Write-Host "No $type record found for $hostname" -ForegroundColor Yellow
            $script:excelResults.Add([PSCustomObject]@{
                Section  = $sectionName
                Record   = $type
                Hostname = $hostname
                Value    = "Not Found"
                Status   = "NOT FOUND"
                Provider = ""
            })
        }
    } catch {
        Write-Host "No $type record found for $hostname" -ForegroundColor Yellow
        $script:excelResults.Add([PSCustomObject]@{
            Section  = $sectionName
            Record   = $type
            Hostname = $hostname
            Value    = "Not Found"
            Status   = "NOT FOUND"
            Provider = ""
        })
    }
}

$sections = @(
    @{ Name = "Main Domain - A Record";                  Hostname = $domain;                                  Type = "A"     }
    @{ Name = "Main Domain - AAAA (IPv6)";               Hostname = $domain;                                  Type = "AAAA"  }
    @{ Name = "Main Domain - MX (Mail)";                 Hostname = $domain;                                  Type = "MX"    }
    @{ Name = "Main Domain - TXT (SPF etc)";             Hostname = $domain;                                  Type = "TXT"   }
    @{ Name = "Main Domain - NS (Nameservers)";          Hostname = $domain;                                  Type = "NS"    }
    @{ Name = "Main Domain - SOA";                       Hostname = $domain;                                  Type = "SOA"   }
    
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

Get-DNSProvider -domain $domain

# CAA record check (uses nslookup as Resolve-DnsName does not support CAA)
Write-Host "`n==============================" -ForegroundColor Green
Write-Host " Main Domain - CAA (SSL Certificate)" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green
try {
    $caaRaw = nslookup -type=CAA $domain 2>&1 | Where-Object { $_ -match "rdata" -or $_ -match "issue" -or $_ -match "CAA" }
    if ($caaRaw) {
        $caaRaw | ForEach-Object { Write-Host $_ }
        $script:excelResults.Add([PSCustomObject]@{
            Section  = "Main Domain - CAA (SSL Certificate)"
            Record   = "CAA"
            Hostname = $domain
            Value    = ($caaRaw -join " ")
            Status   = "FOUND"
            Provider = ""
        })
    } else {
        Write-Host "No CAA record found for $domain" -ForegroundColor Yellow
        $script:excelResults.Add([PSCustomObject]@{
            Section  = "Main Domain - CAA (SSL Certificate)"
            Record   = "CAA"
            Hostname = $domain
            Value    = "Not Found"
            Status   = "NOT FOUND"
            Provider = ""
        })
    }
} catch {
    Write-Host "No CAA record found for $domain" -ForegroundColor Yellow
}

foreach ($section in $sections) {
    Write-Host "`n==============================" -ForegroundColor Green
    Write-Host " $($section.Name)" -ForegroundColor Green
    Write-Host "==============================" -ForegroundColor Green
    Check-DNS -hostname $section.Hostname -type $section.Type -sectionName $section.Name
}

Write-Host "`n============================================" -ForegroundColor Magenta
Write-Host "   AUDIT COMPLETE" -ForegroundColor Magenta
Write-Host "============================================`n" -ForegroundColor Magenta

# ---- Export to Excel with colour coding ----
Write-Host "Exporting to Excel..." -ForegroundColor Cyan

$excel = $excelResults | Export-Excel -Path $outputXlsx -WorksheetName "DNS Audit" -AutoSize -FreezeTopRow -BoldTopRow -PassThru

$ws = $excel.Workbook.Worksheets["DNS Audit"]

# Colour code header row
$ws.Cells["1:1"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
$ws.Cells["1:1"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(63, 84, 163))
$ws.Cells["1:1"].Style.Font.Color.SetColor([System.Drawing.Color]::White)
$ws.Cells["1:1"].Style.Font.Bold = $true

# Colour code rows based on Status
for ($i = 2; $i -le ($excelResults.Count + 1); $i++) {
    $status = $ws.Cells[$i, 5].Value
    $color = switch ($status) {
        "FOUND"     { [System.Drawing.Color]::FromArgb(198, 239, 206) }  # Green
        "NOT FOUND" { [System.Drawing.Color]::FromArgb(255, 199, 206) }  # Red
        "INFO"      { [System.Drawing.Color]::FromArgb(189, 215, 238) }  # Blue
        default     { [System.Drawing.Color]::White }
    }
    $ws.Cells[$i, 1, $i, 6].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $ws.Cells[$i, 1, $i, 6].Style.Fill.BackgroundColor.SetColor($color)
}

# Add title above the table
$ws.InsertRow(1, 3)
$ws.Cells["A1"].Value = "DNS Audit Report"
$ws.Cells["A1"].Style.Font.Size = 16
$ws.Cells["A1"].Style.Font.Bold = $true
$ws.Cells["A2"].Value = "Domain: $domain"
$ws.Cells["A3"].Value = "Date: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')   |   DNS Provider: $providerInfo"
$ws.Cells["A1:F1"].Merge = $true
$ws.Cells["A2:F2"].Merge = $true
$ws.Cells["A3:F3"].Merge = $true

# Apply AutoFilter and FreezePane to row 4 (after title rows)
$ws.Cells["A4:F4"].AutoFilter = $true
$ws.View.FreezePanes(5, 1)

Close-ExcelPackage $excel

Stop-Transcript | Out-Null
Write-Host "TXT Report saved to : $outputTxt" -ForegroundColor Magenta
Write-Host "Excel Report saved to: $outputXlsx" -ForegroundColor Magenta
