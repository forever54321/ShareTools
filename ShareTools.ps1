# ============================================================================
#  ShareTools.ps1 — Single GUI app for home-network folder & printer sharing
#  Right-click -> Run with PowerShell  (auto-elevates to Administrator)
# ============================================================================

# ── Self-elevate to Admin ───────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# ── Assemblies ──────────────────────────────────────────────────────────────
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ══════════════════════════════════════════════════════════════════════════════
# GLOBALS
# ══════════════════════════════════════════════════════════════════════════════
$script:sharedFolders    = @()
$script:sharedPrinters   = @()
$script:setupDone        = $false
$script:hostName         = $null
$script:hostIP           = $null
$script:connected        = $false
$script:infoFolders      = @()
$script:infoPrinters     = @()
$script:shareInfoPath    = Join-Path $PSScriptRoot "ShareInfo.txt"

# ══════════════════════════════════════════════════════════════════════════════
# COLOUR PALETTE
# ══════════════════════════════════════════════════════════════════════════════
$cBg        = [System.Drawing.Color]::FromArgb(30, 30, 30)
$cPanel     = [System.Drawing.Color]::FromArgb(45, 45, 48)
$cText      = [System.Drawing.Color]::FromArgb(220, 220, 220)
$cDimText   = [System.Drawing.Color]::FromArgb(150, 150, 150)
$cAccent    = [System.Drawing.Color]::FromArgb(0, 122, 204)
$cGreen     = [System.Drawing.Color]::FromArgb(46, 160, 67)
$cRed       = [System.Drawing.Color]::FromArgb(200, 60, 60)
$cOrange    = [System.Drawing.Color]::FromArgb(210, 150, 40)
$cBtnHost   = [System.Drawing.Color]::FromArgb(0, 100, 180)
$cBtnClient = [System.Drawing.Color]::FromArgb(35, 134, 54)

$fontTitle  = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$fontBig    = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
$fontNorm   = New-Object System.Drawing.Font("Segoe UI", 10)
$fontSmall  = New-Object System.Drawing.Font("Segoe UI", 9)
$fontMono   = New-Object System.Drawing.Font("Consolas", 9)

# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Get this PC's IP address
# ══════════════════════════════════════════════════════════════════════════════
function Get-LocalIP {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Select-Object -First 1).IPAddress
    if ($ip) { return $ip } else { return "N/A" }
}

# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Log to the output textbox
# ══════════════════════════════════════════════════════════════════════════════
function Write-Log {
    param([System.Windows.Forms.TextBox]$Box, [string]$Msg, [string]$Level = "INFO")
    if (-not $Box) { return }
    $ts = Get-Date -Format "HH:mm:ss"
    $Box.AppendText("[$ts $Level] $Msg`r`n")
    $Box.SelectionStart = $Box.TextLength
    $Box.ScrollToCaret()
}

# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Refresh Host status ListView
# ══════════════════════════════════════════════════════════════════════════════
function Refresh-HostStatus {
    param([System.Windows.Forms.ListView]$LV)
    $LV.Items.Clear()

    # Shared folders
    $allShares = Get-SmbShare -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '^\$|^IPC\$|^ADMIN\$|^C\$|^print\$' -and $_.ShareType -eq 'FileSystemDirectory' }
    foreach ($s in $allShares) {
        $perm = "Read Only"
        $access = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
        if ($access | Where-Object { $_.AccountName -match 'Everyone' -and $_.AccessRight -eq 'Full' }) { $perm = "Read/Write" }
        $item = New-Object System.Windows.Forms.ListViewItem("Folder")
        $item.SubItems.Add("\\$env:COMPUTERNAME\$($s.Name)")
        $item.SubItems.Add($s.Path)
        $item.SubItems.Add($perm)
        $item.ForeColor = $cText
        $LV.Items.Add($item) | Out-Null
    }

    # Shared printers
    $allPrinters = Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Shared -eq $true }
    foreach ($sp in $allPrinters) {
        $item = New-Object System.Windows.Forms.ListViewItem("Printer")
        $item.SubItems.Add("\\$env:COMPUTERNAME\$($sp.ShareName)")
        $item.SubItems.Add($sp.Name)
        $item.SubItems.Add("Shared")
        $item.ForeColor = $cText
        $LV.Items.Add($item) | Out-Null
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Refresh Client status ListView
# ══════════════════════════════════════════════════════════════════════════════
function Refresh-ClientStatus {
    param([System.Windows.Forms.ListView]$LV)
    $LV.Items.Clear()

    # Mapped drives
    $mapped = @()
    try { $mapped = @(Get-WmiObject -Class Win32_MappedLogicalDisk -ErrorAction SilentlyContinue) } catch {}
    if ($mapped.Count -eq 0) {
        $netUseLines = net use 2>$null | Where-Object { $_ -match '\\\\' }
        foreach ($line in $netUseLines) {
            if ($line -match '([A-Z]:)\s+(\\\\[^\s]+)') {
                $mapped += [PSCustomObject]@{ DeviceID = $Matches[1]; ProviderName = $Matches[2] }
            }
        }
    }
    foreach ($d in $mapped) {
        $item = New-Object System.Windows.Forms.ListViewItem("Drive")
        $item.SubItems.Add($d.DeviceID)
        $item.SubItems.Add($d.ProviderName)
        $item.ForeColor = $cText
        $LV.Items.Add($item) | Out-Null
    }

    # Network printers
    $netPrinters = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'Connection' })
    foreach ($p in $netPrinters) {
        $item = New-Object System.Windows.Forms.ListViewItem("Printer")
        $item.SubItems.Add("")
        $item.SubItems.Add($p.Name)
        $item.ForeColor = $cText
        $LV.Items.Add($item) | Out-Null
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Styled button factory
# ══════════════════════════════════════════════════════════════════════════════
function New-StyledButton {
    param(
        [string]$Text,
        [int]$X, [int]$Y,
        [int]$W = 200, [int]$H = 48,
        [System.Drawing.Color]$BgColor = $cAccent,
        [System.Drawing.Font]$Font = $fontNorm
    )
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text      = $Text
    $btn.Location   = New-Object System.Drawing.Point($X, $Y)
    $btn.Size       = New-Object System.Drawing.Size($W, $H)
    $btn.FlatStyle  = 'Flat'
    $btn.FlatAppearance.BorderSize = 0
    $btn.BackColor  = $BgColor
    $btn.ForeColor  = [System.Drawing.Color]::White
    $btn.Font       = $Font
    $btn.Cursor     = [System.Windows.Forms.Cursors]::Hand
    return $btn
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN FORM
# ══════════════════════════════════════════════════════════════════════════════
$form = New-Object System.Windows.Forms.Form
$form.Text            = "ShareTools"
$form.Size            = New-Object System.Drawing.Size(720, 640)
$form.StartPosition   = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox     = $false
$form.BackColor       = $cBg
$form.ForeColor       = $cText
$form.Font            = $fontNorm

# ══════════════════════════════════════════════════════════════════════════════
# PANEL: Launch Screen
# ══════════════════════════════════════════════════════════════════════════════
$panelLaunch = New-Object System.Windows.Forms.Panel
$panelLaunch.Dock      = 'Fill'
$panelLaunch.BackColor = $cBg

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = "ShareTools"
$lblTitle.Font      = $fontTitle
$lblTitle.ForeColor = $cText
$lblTitle.AutoSize  = $true
$lblTitle.Location  = New-Object System.Drawing.Point(260, 40)
$panelLaunch.Controls.Add($lblTitle)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text      = "Home network sharing made easy"
$lblSub.Font      = $fontNorm
$lblSub.ForeColor = $cDimText
$lblSub.AutoSize  = $true
$lblSub.Location  = New-Object System.Drawing.Point(235, 80)
$panelLaunch.Controls.Add($lblSub)

# --- Host button ---
$btnHost = New-StyledButton -Text "Share My Folders && Printers (Host)" -X 140 -Y 160 -W 420 -H 90 -BgColor $cBtnHost -Font $fontBig
$panelLaunch.Controls.Add($btnHost)

$lblHostDesc = New-Object System.Windows.Forms.Label
$lblHostDesc.Text      = "Run on the PC that has the files and printers"
$lblHostDesc.Font      = $fontSmall
$lblHostDesc.ForeColor = $cDimText
$lblHostDesc.AutoSize  = $true
$lblHostDesc.Location  = New-Object System.Drawing.Point(215, 260)
$panelLaunch.Controls.Add($lblHostDesc)

# --- Client button ---
$btnClient = New-StyledButton -Text "Connect to Another PC (Client)" -X 140 -Y 310 -W 420 -H 90 -BgColor $cBtnClient -Font $fontBig
$panelLaunch.Controls.Add($btnClient)

$lblClientDesc = New-Object System.Windows.Forms.Label
$lblClientDesc.Text      = "Run on PCs that want to access shared resources"
$lblClientDesc.Font      = $fontSmall
$lblClientDesc.ForeColor = $cDimText
$lblClientDesc.AutoSize  = $true
$lblClientDesc.Location  = New-Object System.Drawing.Point(200, 410)
$panelLaunch.Controls.Add($lblClientDesc)

# --- Info label ---
$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Text      = "PC: $env:COMPUTERNAME   |   IP: $(Get-LocalIP)   |   Running as Administrator"
$lblInfo.Font      = $fontSmall
$lblInfo.ForeColor = $cDimText
$lblInfo.AutoSize  = $true
$lblInfo.Location  = New-Object System.Drawing.Point(155, 540)
$panelLaunch.Controls.Add($lblInfo)

$form.Controls.Add($panelLaunch)

# ══════════════════════════════════════════════════════════════════════════════
# PANEL: Host Mode
# ══════════════════════════════════════════════════════════════════════════════
$panelHost = New-Object System.Windows.Forms.Panel
$panelHost.Dock      = 'Fill'
$panelHost.BackColor = $cBg
$panelHost.Visible   = $false

# Top bar
$hostTopBar = New-Object System.Windows.Forms.Panel
$hostTopBar.Size      = New-Object System.Drawing.Size(720, 50)
$hostTopBar.Location  = New-Object System.Drawing.Point(0, 0)
$hostTopBar.BackColor = [System.Drawing.Color]::FromArgb(0, 80, 150)

$lblHostTitle = New-Object System.Windows.Forms.Label
$lblHostTitle.Text      = "HOST MODE"
$lblHostTitle.Font      = $fontBig
$lblHostTitle.ForeColor = [System.Drawing.Color]::White
$lblHostTitle.AutoSize  = $true
$lblHostTitle.Location  = New-Object System.Drawing.Point(12, 12)
$hostTopBar.Controls.Add($lblHostTitle)

$lblHostInfo = New-Object System.Windows.Forms.Label
$lblHostInfo.Text      = "$env:COMPUTERNAME  |  $(Get-LocalIP)"
$lblHostInfo.Font      = $fontSmall
$lblHostInfo.ForeColor = [System.Drawing.Color]::FromArgb(180, 210, 255)
$lblHostInfo.AutoSize  = $true
$lblHostInfo.Location  = New-Object System.Drawing.Point(400, 16)
$hostTopBar.Controls.Add($lblHostInfo)

$panelHost.Controls.Add($hostTopBar)

# Back button
$btnHostBack = New-StyledButton -Text "< Back" -X 10 -Y 58 -W 80 -H 32 -BgColor $cPanel -Font $fontSmall
$panelHost.Controls.Add($btnHostBack)

# Network setup status indicator
$lblNetStatus = New-Object System.Windows.Forms.Label
$lblNetStatus.Text      = "Network: Not configured"
$lblNetStatus.Font      = $fontSmall
$lblNetStatus.ForeColor = $cRed
$lblNetStatus.AutoSize  = $true
$lblNetStatus.Location  = New-Object System.Drawing.Point(100, 65)
$panelHost.Controls.Add($lblNetStatus)

# 6 action buttons in a 3x2 grid
$hostBtnY = 100
$hostBtnW = 210
$hostBtnH = 44
$hostBtnGap = 14
$hostBtnX1 = 15
$hostBtnX2 = 15 + $hostBtnW + $hostBtnGap
$hostBtnX3 = 15 + ($hostBtnW + $hostBtnGap) * 2

$btnSetupNet = New-StyledButton -Text "Setup Network"      -X $hostBtnX1 -Y $hostBtnY -W $hostBtnW -H $hostBtnH -BgColor $cAccent
$btnShareFld = New-StyledButton -Text "Share Folders"       -X $hostBtnX2 -Y $hostBtnY -W $hostBtnW -H $hostBtnH -BgColor $cAccent
$btnSharePrt = New-StyledButton -Text "Share Printers"      -X $hostBtnX3 -Y $hostBtnY -W $hostBtnW -H $hostBtnH -BgColor $cAccent

$hostBtnY2 = $hostBtnY + $hostBtnH + 10
$btnRemShare = New-StyledButton -Text "Remove Shares"       -X $hostBtnX1 -Y $hostBtnY2 -W $hostBtnW -H $hostBtnH -BgColor ([System.Drawing.Color]::FromArgb(130, 80, 30))
$btnViewHost = New-StyledButton -Text "View Status"         -X $hostBtnX2 -Y $hostBtnY2 -W $hostBtnW -H $hostBtnH -BgColor ([System.Drawing.Color]::FromArgb(80, 80, 120))
$btnExport   = New-StyledButton -Text "Export Info"         -X $hostBtnX3 -Y $hostBtnY2 -W $hostBtnW -H $hostBtnH -BgColor ([System.Drawing.Color]::FromArgb(80, 80, 120))

$panelHost.Controls.AddRange(@($btnSetupNet, $btnShareFld, $btnSharePrt, $btnRemShare, $btnViewHost, $btnExport))

# Host status ListView
$lblHostLV = New-Object System.Windows.Forms.Label
$lblHostLV.Text     = "Currently Shared:"
$lblHostLV.Font     = $fontSmall
$lblHostLV.ForeColor = $cDimText
$lblHostLV.AutoSize = $true
$lblHostLV.Location = New-Object System.Drawing.Point(15, 210)
$panelHost.Controls.Add($lblHostLV)

$lvHost = New-Object System.Windows.Forms.ListView
$lvHost.Location    = New-Object System.Drawing.Point(15, 230)
$lvHost.Size        = New-Object System.Drawing.Size(672, 160)
$lvHost.View        = 'Details'
$lvHost.FullRowSelect = $true
$lvHost.GridLines   = $true
$lvHost.BackColor   = $cPanel
$lvHost.ForeColor   = $cText
$lvHost.Font        = $fontSmall
$lvHost.BorderStyle = 'None'
$lvHost.HeaderStyle = 'Nonclickable'
$lvHost.Columns.Add("Type",   60)  | Out-Null
$lvHost.Columns.Add("Share",  220) | Out-Null
$lvHost.Columns.Add("Path",   270) | Out-Null
$lvHost.Columns.Add("Access", 100) | Out-Null
$panelHost.Controls.Add($lvHost)

# Host log textbox
$lblHostLog = New-Object System.Windows.Forms.Label
$lblHostLog.Text     = "Log:"
$lblHostLog.Font     = $fontSmall
$lblHostLog.ForeColor = $cDimText
$lblHostLog.AutoSize = $true
$lblHostLog.Location = New-Object System.Drawing.Point(15, 396)
$panelHost.Controls.Add($lblHostLog)

$txtHostLog = New-Object System.Windows.Forms.TextBox
$txtHostLog.Location   = New-Object System.Drawing.Point(15, 414)
$txtHostLog.Size       = New-Object System.Drawing.Size(672, 180)
$txtHostLog.Multiline  = $true
$txtHostLog.ReadOnly   = $true
$txtHostLog.ScrollBars = 'Vertical'
$txtHostLog.BackColor  = [System.Drawing.Color]::FromArgb(20, 20, 20)
$txtHostLog.ForeColor  = [System.Drawing.Color]::FromArgb(180, 220, 180)
$txtHostLog.Font       = $fontMono
$txtHostLog.BorderStyle = 'None'
$panelHost.Controls.Add($txtHostLog)

$form.Controls.Add($panelHost)

# ══════════════════════════════════════════════════════════════════════════════
# PANEL: Client Mode
# ══════════════════════════════════════════════════════════════════════════════
$panelClient = New-Object System.Windows.Forms.Panel
$panelClient.Dock      = 'Fill'
$panelClient.BackColor = $cBg
$panelClient.Visible   = $false

# Top bar
$clientTopBar = New-Object System.Windows.Forms.Panel
$clientTopBar.Size      = New-Object System.Drawing.Size(720, 50)
$clientTopBar.Location  = New-Object System.Drawing.Point(0, 0)
$clientTopBar.BackColor = [System.Drawing.Color]::FromArgb(25, 100, 40)

$lblClientTitle = New-Object System.Windows.Forms.Label
$lblClientTitle.Text      = "CLIENT MODE"
$lblClientTitle.Font      = $fontBig
$lblClientTitle.ForeColor = [System.Drawing.Color]::White
$lblClientTitle.AutoSize  = $true
$lblClientTitle.Location  = New-Object System.Drawing.Point(12, 12)
$clientTopBar.Controls.Add($lblClientTitle)

$lblClientInfo = New-Object System.Windows.Forms.Label
$lblClientInfo.Text      = "Not connected"
$lblClientInfo.Font      = $fontSmall
$lblClientInfo.ForeColor = [System.Drawing.Color]::FromArgb(180, 255, 180)
$lblClientInfo.AutoSize  = $true
$lblClientInfo.Location  = New-Object System.Drawing.Point(450, 16)
$clientTopBar.Controls.Add($lblClientInfo)

$panelClient.Controls.Add($clientTopBar)

# Back button
$btnClientBack = New-StyledButton -Text "< Back" -X 10 -Y 58 -W 80 -H 32 -BgColor $cPanel -Font $fontSmall
$panelClient.Controls.Add($btnClientBack)

# Host connect bar
$lblConnectTo = New-Object System.Windows.Forms.Label
$lblConnectTo.Text     = "Host PC:"
$lblConnectTo.Font     = $fontSmall
$lblConnectTo.ForeColor = $cDimText
$lblConnectTo.AutoSize = $true
$lblConnectTo.Location = New-Object System.Drawing.Point(110, 65)
$panelClient.Controls.Add($lblConnectTo)

$txtHostAddr = New-Object System.Windows.Forms.TextBox
$txtHostAddr.Location  = New-Object System.Drawing.Point(170, 61)
$txtHostAddr.Size      = New-Object System.Drawing.Size(250, 28)
$txtHostAddr.Font      = $fontNorm
$txtHostAddr.BackColor = $cPanel
$txtHostAddr.ForeColor = $cText
$txtHostAddr.BorderStyle = 'FixedSingle'
$panelClient.Controls.Add($txtHostAddr)

$btnConnect = New-StyledButton -Text "Connect" -X 430 -Y 58 -W 100 -H 32 -BgColor $cBtnClient -Font $fontSmall
$panelClient.Controls.Add($btnConnect)

$lblConnStatus = New-Object System.Windows.Forms.Label
$lblConnStatus.Text     = ""
$lblConnStatus.Font     = $fontSmall
$lblConnStatus.ForeColor = $cDimText
$lblConnStatus.AutoSize = $true
$lblConnStatus.Location = New-Object System.Drawing.Point(540, 65)
$panelClient.Controls.Add($lblConnStatus)

# 4 action buttons in a row
$clBtnY = 100
$clBtnW = 160
$clBtnH = 44
$clBtnGap = 10
$clBtnX = 15

$btnMapDrv   = New-StyledButton -Text "Map Drives"       -X $clBtnX                              -Y $clBtnY -W $clBtnW -H $clBtnH -BgColor $cAccent
$btnConPrt   = New-StyledButton -Text "Connect Printers"  -X ($clBtnX + $clBtnW + $clBtnGap)      -Y $clBtnY -W $clBtnW -H $clBtnH -BgColor $cAccent
$btnDiscon   = New-StyledButton -Text "Disconnect"        -X ($clBtnX + ($clBtnW + $clBtnGap)*2)  -Y $clBtnY -W $clBtnW -H $clBtnH -BgColor ([System.Drawing.Color]::FromArgb(130, 80, 30))
$btnViewCli  = New-StyledButton -Text "View Status"       -X ($clBtnX + ($clBtnW + $clBtnGap)*3)  -Y $clBtnY -W $clBtnW -H $clBtnH -BgColor ([System.Drawing.Color]::FromArgb(80, 80, 120))

$panelClient.Controls.AddRange(@($btnMapDrv, $btnConPrt, $btnDiscon, $btnViewCli))

# Client status ListView
$lblCliLV = New-Object System.Windows.Forms.Label
$lblCliLV.Text     = "Current Connections:"
$lblCliLV.Font     = $fontSmall
$lblCliLV.ForeColor = $cDimText
$lblCliLV.AutoSize = $true
$lblCliLV.Location = New-Object System.Drawing.Point(15, 155)
$panelClient.Controls.Add($lblCliLV)

$lvClient = New-Object System.Windows.Forms.ListView
$lvClient.Location    = New-Object System.Drawing.Point(15, 175)
$lvClient.Size        = New-Object System.Drawing.Size(672, 160)
$lvClient.View        = 'Details'
$lvClient.FullRowSelect = $true
$lvClient.GridLines   = $true
$lvClient.BackColor   = $cPanel
$lvClient.ForeColor   = $cText
$lvClient.Font        = $fontSmall
$lvClient.BorderStyle = 'None'
$lvClient.HeaderStyle = 'Nonclickable'
$lvClient.Columns.Add("Type",    60) | Out-Null
$lvClient.Columns.Add("Drive",   70) | Out-Null
$lvClient.Columns.Add("Remote", 520) | Out-Null
$panelClient.Controls.Add($lvClient)

# Client log textbox
$lblCliLog = New-Object System.Windows.Forms.Label
$lblCliLog.Text     = "Log:"
$lblCliLog.Font     = $fontSmall
$lblCliLog.ForeColor = $cDimText
$lblCliLog.AutoSize = $true
$lblCliLog.Location = New-Object System.Drawing.Point(15, 341)
$panelClient.Controls.Add($lblCliLog)

$txtCliLog = New-Object System.Windows.Forms.TextBox
$txtCliLog.Location   = New-Object System.Drawing.Point(15, 359)
$txtCliLog.Size       = New-Object System.Drawing.Size(672, 235)
$txtCliLog.Multiline  = $true
$txtCliLog.ReadOnly   = $true
$txtCliLog.ScrollBars = 'Vertical'
$txtCliLog.BackColor  = [System.Drawing.Color]::FromArgb(20, 20, 20)
$txtCliLog.ForeColor  = [System.Drawing.Color]::FromArgb(180, 220, 180)
$txtCliLog.Font       = $fontMono
$txtCliLog.BorderStyle = 'None'
$panelClient.Controls.Add($txtCliLog)

$form.Controls.Add($panelClient)

# ══════════════════════════════════════════════════════════════════════════════
# NAVIGATION
# ══════════════════════════════════════════════════════════════════════════════
function Show-Panel {
    param([string]$Name)
    $panelLaunch.Visible  = ($Name -eq 'Launch')
    $panelHost.Visible    = ($Name -eq 'Host')
    $panelClient.Visible  = ($Name -eq 'Client')
    if ($Name -eq 'Host')   { Refresh-HostStatus -LV $lvHost }
    if ($Name -eq 'Client') { Refresh-ClientStatus -LV $lvClient }
}

$btnHost.Add_Click({       Show-Panel 'Host' })
$btnClient.Add_Click({     Show-Panel 'Client' })
$btnHostBack.Add_Click({   Show-Panel 'Launch' })
$btnClientBack.Add_Click({ Show-Panel 'Launch' })

# ══════════════════════════════════════════════════════════════════════════════
# HOST — Setup Network
# ══════════════════════════════════════════════════════════════════════════════
$btnSetupNet.Add_Click({
    $log = $txtHostLog

    # Ask about password-free sharing
    $pwdResult = [System.Windows.Forms.MessageBox]::Show(
        "Disable password-protected sharing?`n`nChoose YES for easy home access (no credentials needed).`nChoose NO to keep password protection.",
        "Password Sharing", 'YesNo', 'Question')
    $disablePwd = ($pwdResult -eq 'Yes')

    Write-Log $log "Configuring network sharing services..." "WORK"

    # Firewall
    try {
        Get-NetFirewallRule -DisplayGroup "Network Discovery" -ErrorAction SilentlyContinue |
            Set-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue
        Write-Log $log "Network Discovery firewall rules enabled" "OK"
    } catch { Write-Log $log "Network Discovery rules: $_" "FAIL" }

    try {
        Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue |
            Set-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue
        Write-Log $log "File & Printer Sharing firewall rules enabled" "OK"
    } catch { Write-Log $log "File & Printer Sharing rules: $_" "FAIL" }

    # Services
    $services = @(
        @{ Name="LanmanServer"; Friendly="File Sharing Server" },
        @{ Name="FDResPub";     Friendly="Device Discovery" },
        @{ Name="SSDPSRV";      Friendly="Network Search" },
        @{ Name="upnphost";     Friendly="UPnP Device Host" },
        @{ Name="dnscache";     Friendly="DNS Client" },
        @{ Name="Spooler";      Friendly="Print Spooler" }
    )
    foreach ($svc in $services) {
        try {
            $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if ($s) {
                if ($s.StartType -eq 'Disabled') { Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction SilentlyContinue }
                if ($s.Status -ne 'Running')     { Start-Service -Name $svc.Name -ErrorAction SilentlyContinue }
                Write-Log $log "$($svc.Friendly) service running" "OK"
            }
        } catch { Write-Log $log "$($svc.Friendly) skipped" "WARN" }
    }

    # SMB2
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Write-Log $log "SMB2 protocol enabled" "OK"
    } catch { Write-Log $log "SMB2 tweak skipped" "WARN" }

    # Private network
    try {
        $adapters = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -ne 'Private' }
        foreach ($a in $adapters) {
            Set-NetConnectionProfile -InterfaceIndex $a.InterfaceIndex -NetworkCategory Private -ErrorAction SilentlyContinue
            Write-Log $log "Adapter '$($a.Name)' set to Private" "OK"
        }
        if (-not $adapters) { Write-Log $log "All adapters already Private" "OK" }
    } catch { Write-Log $log "Could not change network profile" "WARN" }

    # Password sharing
    if ($disablePwd) {
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "everyoneincludesanonymous" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            net user Guest /active:yes 2>$null | Out-Null
            Write-Log $log "Password-free home sharing enabled" "OK"
        } catch { Write-Log $log "Partial password config: $_" "WARN" }
    } else {
        Write-Log $log "Password protection kept - clients need your PC credentials" "INFO"
    }

    $script:setupDone = $true
    $lblNetStatus.Text      = "Network: Configured"
    $lblNetStatus.ForeColor = $cGreen
    Write-Log $log "Network sharing is now ENABLED!" "OK"
    [System.Windows.Forms.MessageBox]::Show("Network sharing configured successfully!", "Setup Network", 'OK', 'Information')
})

# ══════════════════════════════════════════════════════════════════════════════
# HOST — Share Folders
# ══════════════════════════════════════════════════════════════════════════════
$btnShareFld.Add_Click({
    $log = $txtHostLog

    # Folder browser
    $browser = New-Object System.Windows.Forms.FolderBrowserDialog
    $browser.Description       = "Pick a folder to share on your home network"
    $browser.ShowNewFolderButton = $false
    $result = $browser.ShowDialog()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Log $log "Folder selection cancelled" "INFO"
        return
    }
    $folderPath = $browser.SelectedPath

    # Share name
    $defaultName = (Split-Path $folderPath -Leaf) -replace '[^\w\-\.]', '_'
    $inputName = [Microsoft.VisualBasic.Interaction]::InputBox(
        "Share name for:`n$folderPath", "Share Name", $defaultName)
    if ([string]::IsNullOrWhiteSpace($inputName)) { $inputName = $defaultName }

    # Permission dialog
    $permForm = New-Object System.Windows.Forms.Form
    $permForm.Text            = "Permission Level"
    $permForm.Size            = New-Object System.Drawing.Size(340, 190)
    $permForm.StartPosition   = 'CenterParent'
    $permForm.FormBorderStyle = 'FixedDialog'
    $permForm.MaximizeBox     = $false
    $permForm.MinimizeBox     = $false
    $permForm.BackColor       = $cBg
    $permForm.ForeColor       = $cText

    $lblPerm = New-Object System.Windows.Forms.Label
    $lblPerm.Text     = "Choose permission for '$inputName':"
    $lblPerm.Location = New-Object System.Drawing.Point(15, 15)
    $lblPerm.AutoSize = $true
    $permForm.Controls.Add($lblPerm)

    $rbRead = New-Object System.Windows.Forms.RadioButton
    $rbRead.Text     = "Read Only (Recommended)"
    $rbRead.Location = New-Object System.Drawing.Point(30, 45)
    $rbRead.AutoSize = $true
    $rbRead.ForeColor = $cText
    $rbRead.Checked  = $true
    $permForm.Controls.Add($rbRead)

    $rbWrite = New-Object System.Windows.Forms.RadioButton
    $rbWrite.Text     = "Read && Write"
    $rbWrite.Location = New-Object System.Drawing.Point(30, 75)
    $rbWrite.AutoSize = $true
    $rbWrite.ForeColor = $cText
    $permForm.Controls.Add($rbWrite)

    $btnPermOK = New-StyledButton -Text "OK" -X 110 -Y 110 -W 100 -H 32 -BgColor $cAccent -Font $fontSmall
    $btnPermOK.DialogResult = 'OK'
    $permForm.Controls.Add($btnPermOK)
    $permForm.AcceptButton = $btnPermOK

    $permResult = $permForm.ShowDialog()
    if ($permResult -ne 'OK') {
        Write-Log $log "Share cancelled" "INFO"
        return
    }
    $readOnly  = $rbRead.Checked
    $permLabel = if ($readOnly) { "Read Only" } else { "Read/Write" }

    # Confirm
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Create share?`n`nShare: \\$env:COMPUTERNAME\$inputName`nPath: $folderPath`nAccess: $permLabel",
        "Confirm Share", 'YesNo', 'Question')
    if ($confirm -ne 'Yes') {
        Write-Log $log "Share creation cancelled" "INFO"
        return
    }

    # Remove existing
    $existing = Get-SmbShare -Name $inputName -ErrorAction SilentlyContinue
    if ($existing) { Remove-SmbShare -Name $inputName -Force -ErrorAction SilentlyContinue }

    try {
        if ($readOnly) {
            New-SmbShare -Name $inputName -Path $folderPath -ReadAccess "Everyone" -FullAccess "Administrators" -ErrorAction Stop | Out-Null
        } else {
            New-SmbShare -Name $inputName -Path $folderPath -FullAccess "Everyone" -ErrorAction Stop | Out-Null
        }

        # NTFS ACL
        $acl  = Get-Acl $folderPath
        $perm = if ($readOnly) { "ReadAndExecute" } else { "FullControl" }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", $perm, "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -Path $folderPath -AclObject $acl -ErrorAction SilentlyContinue

        $script:sharedFolders += [PSCustomObject]@{ Name=$inputName; Path=$folderPath; Permission=$permLabel }
        Write-Log $log "Shared: \\$env:COMPUTERNAME\$inputName  ($permLabel)" "OK"
        Refresh-HostStatus -LV $lvHost
        [System.Windows.Forms.MessageBox]::Show(
            "Folder shared!`n\\$env:COMPUTERNAME\$inputName ($permLabel)", "Success", 'OK', 'Information')
    } catch {
        Write-Log $log "Failed to share folder: $_" "FAIL"
        [System.Windows.Forms.MessageBox]::Show("Error: $_", "Share Failed", 'OK', 'Error')
    }
})

# ══════════════════════════════════════════════════════════════════════════════
# HOST — Share Printers
# ══════════════════════════════════════════════════════════════════════════════
$btnSharePrt.Add_Click({
    $log = $txtHostLog
    $printers = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Type -ne 'Connection' })

    if ($printers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No local printers detected.", "Share Printers", 'OK', 'Warning')
        return
    }

    # Build picker form
    $prtForm = New-Object System.Windows.Forms.Form
    $prtForm.Text            = "Share Printers"
    $prtForm.Size            = New-Object System.Drawing.Size(420, 350)
    $prtForm.StartPosition   = 'CenterParent'
    $prtForm.FormBorderStyle = 'FixedDialog'
    $prtForm.MaximizeBox     = $false
    $prtForm.MinimizeBox     = $false
    $prtForm.BackColor       = $cBg
    $prtForm.ForeColor       = $cText

    $lblPick = New-Object System.Windows.Forms.Label
    $lblPick.Text     = "Select printers to share:"
    $lblPick.Location = New-Object System.Drawing.Point(15, 12)
    $lblPick.AutoSize = $true
    $prtForm.Controls.Add($lblPick)

    $clbPrinters = New-Object System.Windows.Forms.CheckedListBox
    $clbPrinters.Location  = New-Object System.Drawing.Point(15, 38)
    $clbPrinters.Size      = New-Object System.Drawing.Size(372, 210)
    $clbPrinters.BackColor = $cPanel
    $clbPrinters.ForeColor = $cText
    $clbPrinters.Font      = $fontSmall
    $clbPrinters.BorderStyle = 'None'
    $clbPrinters.CheckOnClick = $true
    foreach ($p in $printers) {
        $status = if ($p.Shared) { " [already shared]" } else { "" }
        $clbPrinters.Items.Add("$($p.Name)$status", $p.Shared) | Out-Null
    }
    $prtForm.Controls.Add($clbPrinters)

    $btnAllPrt = New-StyledButton -Text "Select All" -X 15 -Y 260 -W 100 -H 32 -BgColor $cPanel -Font $fontSmall
    $btnAllPrt.Add_Click({ for ($i = 0; $i -lt $clbPrinters.Items.Count; $i++) { $clbPrinters.SetItemChecked($i, $true) } })
    $prtForm.Controls.Add($btnAllPrt)

    $btnPrtOK = New-StyledButton -Text "Share Selected" -X 240 -Y 260 -W 145 -H 32 -BgColor $cBtnClient -Font $fontSmall
    $btnPrtOK.DialogResult = 'OK'
    $prtForm.Controls.Add($btnPrtOK)
    $prtForm.AcceptButton = $btnPrtOK

    $prtResult = $prtForm.ShowDialog()
    if ($prtResult -ne 'OK') { return }

    $sharedCount = 0
    for ($i = 0; $i -lt $clbPrinters.Items.Count; $i++) {
        if ($clbPrinters.GetItemChecked($i)) {
            $p = $printers[$i]
            $sName = ($p.Name -replace '[^\w\-\.]', '_')
            try {
                Set-Printer -Name $p.Name -Shared $true -ShareName $sName -ErrorAction Stop
                Write-Log $log "Shared printer: $($p.Name) -> \\$env:COMPUTERNAME\$sName" "OK"
                $script:sharedPrinters += [PSCustomObject]@{ Name=$p.Name; ShareName=$sName }
                $sharedCount++
            } catch {
                Write-Log $log "Failed to share '$($p.Name)': $_" "FAIL"
            }
        }
    }
    Refresh-HostStatus -LV $lvHost
    if ($sharedCount -gt 0) {
        [System.Windows.Forms.MessageBox]::Show("$sharedCount printer(s) shared!", "Success", 'OK', 'Information')
    }
})

# ══════════════════════════════════════════════════════════════════════════════
# HOST — Remove Shares
# ══════════════════════════════════════════════════════════════════════════════
$btnRemShare.Add_Click({
    $log = $txtHostLog

    # Collect current shares
    $allShares = @(Get-SmbShare -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '^\$|^IPC\$|^ADMIN\$|^C\$|^print\$' -and $_.ShareType -eq 'FileSystemDirectory' })
    $allPrinters = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Shared -eq $true })

    if ($allShares.Count -eq 0 -and $allPrinters.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Nothing is currently shared.", "Remove Shares", 'OK', 'Information')
        return
    }

    # Build picker form
    $remForm = New-Object System.Windows.Forms.Form
    $remForm.Text            = "Remove Shares"
    $remForm.Size            = New-Object System.Drawing.Size(460, 380)
    $remForm.StartPosition   = 'CenterParent'
    $remForm.FormBorderStyle = 'FixedDialog'
    $remForm.MaximizeBox     = $false
    $remForm.MinimizeBox     = $false
    $remForm.BackColor       = $cBg
    $remForm.ForeColor       = $cText

    $lblRemPick = New-Object System.Windows.Forms.Label
    $lblRemPick.Text     = "Select items to remove:"
    $lblRemPick.Location = New-Object System.Drawing.Point(15, 12)
    $lblRemPick.AutoSize = $true
    $remForm.Controls.Add($lblRemPick)

    $clbRemove = New-Object System.Windows.Forms.CheckedListBox
    $clbRemove.Location  = New-Object System.Drawing.Point(15, 38)
    $clbRemove.Size      = New-Object System.Drawing.Size(412, 240)
    $clbRemove.BackColor = $cPanel
    $clbRemove.ForeColor = $cText
    $clbRemove.Font      = $fontSmall
    $clbRemove.BorderStyle = 'None'
    $clbRemove.CheckOnClick = $true

    # Track items
    $removeItems = @()
    foreach ($s in $allShares) {
        $clbRemove.Items.Add("[Folder] \\$env:COMPUTERNAME\$($s.Name)  ->  $($s.Path)") | Out-Null
        $removeItems += @{ Type="Folder"; Name=$s.Name }
    }
    foreach ($p in $allPrinters) {
        $clbRemove.Items.Add("[Printer] $($p.Name)  (\\$env:COMPUTERNAME\$($p.ShareName))") | Out-Null
        $removeItems += @{ Type="Printer"; Name=$p.Name; ShareName=$p.ShareName }
    }
    $remForm.Controls.Add($clbRemove)

    $btnRemOK = New-StyledButton -Text "Remove Selected" -X 280 -Y 290 -W 145 -H 32 -BgColor $cRed -Font $fontSmall
    $btnRemOK.DialogResult = 'OK'
    $remForm.Controls.Add($btnRemOK)
    $remForm.AcceptButton = $btnRemOK

    $remResult = $remForm.ShowDialog()
    if ($remResult -ne 'OK') { return }

    $removedCount = 0
    for ($i = 0; $i -lt $clbRemove.Items.Count; $i++) {
        if ($clbRemove.GetItemChecked($i)) {
            $item = $removeItems[$i]
            if ($item.Type -eq "Folder") {
                try {
                    Remove-SmbShare -Name $item.Name -Force -ErrorAction Stop
                    Write-Log $log "Removed folder share: $($item.Name)" "OK"
                    $script:sharedFolders = @($script:sharedFolders | Where-Object { $_.Name -ne $item.Name })
                    $removedCount++
                } catch { Write-Log $log "Failed to remove '$($item.Name)': $_" "FAIL" }
            } elseif ($item.Type -eq "Printer") {
                try {
                    Set-Printer -Name $item.Name -Shared $false -ErrorAction Stop
                    Write-Log $log "Unshared printer: $($item.Name)" "OK"
                    $script:sharedPrinters = @($script:sharedPrinters | Where-Object { $_.Name -ne $item.Name })
                    $removedCount++
                } catch { Write-Log $log "Failed to unshare '$($item.Name)': $_" "FAIL" }
            }
        }
    }
    Refresh-HostStatus -LV $lvHost
    if ($removedCount -gt 0) {
        [System.Windows.Forms.MessageBox]::Show("$removedCount item(s) removed.", "Done", 'OK', 'Information')
    }
})

# ══════════════════════════════════════════════════════════════════════════════
# HOST — View Status
# ══════════════════════════════════════════════════════════════════════════════
$btnViewHost.Add_Click({
    Refresh-HostStatus -LV $lvHost
    $log = $txtHostLog
    $ip = Get-LocalIP
    $folderCount  = ($lvHost.Items | Where-Object { $_.Text -eq "Folder" }).Count
    $printerCount = ($lvHost.Items | Where-Object { $_.Text -eq "Printer" }).Count
    $netLabel = if ($script:setupDone) { "Configured" } else { "Not configured" }
    Write-Log $log "--- Status Dashboard ---" "INFO"
    Write-Log $log "Computer: $env:COMPUTERNAME  |  IP: $ip  |  Network: $netLabel" "INFO"
    Write-Log $log "Shared folders: $folderCount  |  Shared printers: $printerCount" "INFO"
    Write-Log $log "Clients should connect to: \\$env:COMPUTERNAME or \\$ip" "INFO"
})

# ══════════════════════════════════════════════════════════════════════════════
# HOST — Export Info
# ══════════════════════════════════════════════════════════════════════════════
$btnExport.Add_Click({
    $log = $txtHostLog
    $ip = Get-LocalIP
    $exportPath = $script:shareInfoPath

    $lines = @(
        "HOST=$env:COMPUTERNAME"
        "IP=$ip"
    )

    $allShares = Get-SmbShare -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '^\$|^IPC\$|^ADMIN\$|^C\$|^print\$' -and $_.ShareType -eq 'FileSystemDirectory' }
    foreach ($s in $allShares) {
        $perm = "Read Only"
        $access = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
        if ($access | Where-Object { $_.AccountName -match 'Everyone' -and $_.AccessRight -eq 'Full' }) { $perm = "Read/Write" }
        $lines += "FOLDER=$($s.Name)|$perm"
    }

    $allPrinters = Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Shared -eq $true }
    foreach ($sp in $allPrinters) { $lines += "PRINTER=$($sp.ShareName)" }

    $lines | Set-Content -Path $exportPath -Encoding UTF8
    Write-Log $log "Exported to: $exportPath" "OK"

    $openResult = [System.Windows.Forms.MessageBox]::Show(
        "ShareInfo.txt saved to:`n$exportPath`n`nCopy this file alongside ShareTools.ps1 on client PCs.`n`nOpen the folder?",
        "Export Complete", 'YesNo', 'Information')
    if ($openResult -eq 'Yes') { explorer.exe $PSScriptRoot }
})

# ══════════════════════════════════════════════════════════════════════════════
# CLIENT — Connect to Host
# ══════════════════════════════════════════════════════════════════════════════
$btnConnect.Add_Click({
    $log = $txtCliLog
    $addr = $txtHostAddr.Text.Trim()

    if ([string]::IsNullOrWhiteSpace($addr)) {
        # Try ShareInfo.txt
        if (Test-Path $script:shareInfoPath) {
            $infoLines = Get-Content $script:shareInfoPath -Encoding UTF8
            $fileHost = ($infoLines | Where-Object { $_ -match '^HOST=' }) -replace '^HOST=', ''
            $fileIP   = ($infoLines | Where-Object { $_ -match '^IP=' })   -replace '^IP=', ''
            $script:infoFolders  = @($infoLines | Where-Object { $_ -match '^FOLDER=' }  | ForEach-Object { ($_ -replace '^FOLDER=', '').Split('|')[0] })
            $script:infoPrinters = @($infoLines | Where-Object { $_ -match '^PRINTER=' } | ForEach-Object { $_ -replace '^PRINTER=', '' })

            $useFile = [System.Windows.Forms.MessageBox]::Show(
                "ShareInfo.txt found!`nHost: $fileHost`nIP: $fileIP`n`nConnect to this host?",
                "Auto-Detected Host", 'YesNo', 'Question')
            if ($useFile -eq 'Yes') {
                $addr = $fileHost
                $txtHostAddr.Text = $addr
            } else { return }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Enter a host PC name or IP address.", "Connect", 'OK', 'Warning')
            return
        }
    }

    # Enable client-side networking
    Write-Log $log "Preparing network..." "WORK"
    try {
        Get-NetFirewallRule -DisplayGroup "Network Discovery" -ErrorAction SilentlyContinue |
            Set-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue
        Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue |
            Set-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Write-Log $log "Client network configured" "OK"
    } catch { Write-Log $log "Network prep warning: $_" "WARN" }

    # Set private network
    try {
        $adapters = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -ne 'Private' }
        foreach ($a in $adapters) {
            Set-NetConnectionProfile -InterfaceIndex $a.InterfaceIndex -NetworkCategory Private -ErrorAction SilentlyContinue
        }
    } catch {}

    # Ping test
    Write-Log $log "Pinging $addr..." "WORK"
    $lblConnStatus.Text = "Connecting..."
    $lblConnStatus.ForeColor = $cOrange
    [System.Windows.Forms.Application]::DoEvents()

    $ping = Test-Connection -ComputerName $addr -Count 2 -Quiet -ErrorAction SilentlyContinue
    if ($ping) {
        $script:hostName  = $addr
        $script:connected = $true
        $lblConnStatus.Text = "Connected"
        $lblConnStatus.ForeColor = $cGreen
        $lblClientInfo.Text = "Connected to \\$addr"
        Write-Log $log "Host '$addr' is reachable!" "OK"

        # Try to load ShareInfo if we connected from typed address
        if ($script:infoFolders.Count -eq 0 -and (Test-Path $script:shareInfoPath)) {
            $infoLines = Get-Content $script:shareInfoPath -Encoding UTF8
            $script:infoFolders  = @($infoLines | Where-Object { $_ -match '^FOLDER=' }  | ForEach-Object { ($_ -replace '^FOLDER=', '').Split('|')[0] })
            $script:infoPrinters = @($infoLines | Where-Object { $_ -match '^PRINTER=' } | ForEach-Object { $_ -replace '^PRINTER=', '' })
        }
    } else {
        Write-Log $log "Cannot ping '$addr'" "WARN"
        $contResult = [System.Windows.Forms.MessageBox]::Show(
            "Cannot reach '$addr'.`n`nPossible causes:`n- Different Wi-Fi network`n- Firewall blocking ping`n- Incorrect name/IP`n`nContinue anyway? (might work if ping is blocked)",
            "Connection Warning", 'YesNo', 'Warning')
        if ($contResult -eq 'Yes') {
            $script:hostName  = $addr
            $script:connected = $true
            $lblConnStatus.Text = "Connected (unverified)"
            $lblConnStatus.ForeColor = $cOrange
            $lblClientInfo.Text = "\\$addr (unverified)"
            Write-Log $log "Continuing with unverified connection to '$addr'" "WARN"
        } else {
            $lblConnStatus.Text = "Failed"
            $lblConnStatus.ForeColor = $cRed
        }
    }
    Refresh-ClientStatus -LV $lvClient
})

# Also handle Enter key in the address textbox
$txtHostAddr.Add_KeyDown({
    if ($_.KeyCode -eq 'Return') { $btnConnect.PerformClick() }
})

# Auto-fill from ShareInfo.txt on panel load
$panelClient.Add_VisibleChanged({
    if ($panelClient.Visible -and [string]::IsNullOrWhiteSpace($txtHostAddr.Text) -and (Test-Path $script:shareInfoPath)) {
        $infoLines = Get-Content $script:shareInfoPath -Encoding UTF8
        $fileHost = ($infoLines | Where-Object { $_ -match '^HOST=' }) -replace '^HOST=', ''
        if ($fileHost) { $txtHostAddr.Text = $fileHost }
    }
})

# ══════════════════════════════════════════════════════════════════════════════
# CLIENT — Map Drives
# ══════════════════════════════════════════════════════════════════════════════
$btnMapDrv.Add_Click({
    $log = $txtCliLog
    if (-not $script:hostName) {
        [System.Windows.Forms.MessageBox]::Show("Connect to a host first!", "Map Drives", 'OK', 'Warning')
        return
    }

    Write-Log $log "Discovering shares on \\$($script:hostName)..." "WORK"
    [System.Windows.Forms.Application]::DoEvents()

    $shares = @()
    try {
        $shares = @(Get-SmbShare -CimSession $script:hostName -ErrorAction Stop |
            Where-Object { $_.Name -notmatch '^\$|^IPC\$|^ADMIN\$|^C\$|^print\$' -and $_.ShareType -eq 'FileSystemDirectory' })
    } catch {
        try {
            $netView = net view "\\$($script:hostName)" 2>&1
            $shareLines = $netView | Where-Object { $_ -match '^\s*\S+\s+Disk' }
            foreach ($line in $shareLines) {
                if ($line -match '^\s*(\S+)\s+Disk') {
                    $shares += [PSCustomObject]@{ Name = $Matches[1] }
                }
            }
        } catch { }
    }

    # Fallback to ShareInfo.txt
    if ($shares.Count -eq 0 -and $script:infoFolders.Count -gt 0) {
        foreach ($f in $script:infoFolders) {
            $shares += [PSCustomObject]@{ Name = $f }
        }
        Write-Log $log "Using share names from ShareInfo.txt" "INFO"
    }

    if ($shares.Count -eq 0) {
        $manualName = [Microsoft.VisualBasic.Interaction]::InputBox(
            "No shares found on \\$($script:hostName).`nEnter a share name manually (or leave blank to cancel):",
            "Manual Share Name", "")
        if ([string]::IsNullOrWhiteSpace($manualName)) { return }
        $shares += [PSCustomObject]@{ Name = $manualName }
    }

    # Build picker form
    $mapForm = New-Object System.Windows.Forms.Form
    $mapForm.Text            = "Map Network Drives"
    $mapForm.Size            = New-Object System.Drawing.Size(520, 420)
    $mapForm.StartPosition   = 'CenterParent'
    $mapForm.FormBorderStyle = 'FixedDialog'
    $mapForm.MaximizeBox     = $false
    $mapForm.MinimizeBox     = $false
    $mapForm.BackColor       = $cBg
    $mapForm.ForeColor       = $cText

    $lblMapPick = New-Object System.Windows.Forms.Label
    $lblMapPick.Text     = "Shares on \\$($script:hostName):"
    $lblMapPick.Location = New-Object System.Drawing.Point(15, 12)
    $lblMapPick.AutoSize = $true
    $mapForm.Controls.Add($lblMapPick)

    $clbShares = New-Object System.Windows.Forms.CheckedListBox
    $clbShares.Location  = New-Object System.Drawing.Point(15, 38)
    $clbShares.Size      = New-Object System.Drawing.Size(470, 160)
    $clbShares.BackColor = $cPanel
    $clbShares.ForeColor = $cText
    $clbShares.Font      = $fontSmall
    $clbShares.BorderStyle = 'None'
    $clbShares.CheckOnClick = $true
    foreach ($s in $shares) {
        $clbShares.Items.Add("\\$($script:hostName)\$($s.Name)", $true) | Out-Null
    }
    $mapForm.Controls.Add($clbShares)

    # Drive letter assignment
    $usedLetters = @((Get-PSDrive -PSProvider FileSystem).Name)
    $availableLetters = @([char[]]('D'..'Z') | Where-Object { [string]$_ -notin $usedLetters })

    $lblDrive = New-Object System.Windows.Forms.Label
    $lblDrive.Text     = "Starting drive letter:"
    $lblDrive.Location = New-Object System.Drawing.Point(15, 210)
    $lblDrive.AutoSize = $true
    $mapForm.Controls.Add($lblDrive)

    $cbDrive = New-Object System.Windows.Forms.ComboBox
    $cbDrive.Location  = New-Object System.Drawing.Point(170, 207)
    $cbDrive.Size      = New-Object System.Drawing.Size(60, 28)
    $cbDrive.BackColor = $cPanel
    $cbDrive.ForeColor = $cText
    $cbDrive.Font      = $fontSmall
    $cbDrive.DropDownStyle = 'DropDownList'
    foreach ($l in $availableLetters) { $cbDrive.Items.Add("${l}:") | Out-Null }
    if ($cbDrive.Items.Count -gt 0) { $cbDrive.SelectedIndex = 0 }
    $mapForm.Controls.Add($cbDrive)

    # Persistent checkbox
    $chkPersist = New-Object System.Windows.Forms.CheckBox
    $chkPersist.Text     = "Reconnect at login (persistent)"
    $chkPersist.Location = New-Object System.Drawing.Point(15, 250)
    $chkPersist.AutoSize = $true
    $chkPersist.ForeColor = $cText
    $chkPersist.Checked  = $true
    $mapForm.Controls.Add($chkPersist)

    $btnMapOK = New-StyledButton -Text "Map Selected" -X 350 -Y 330 -W 140 -H 35 -BgColor $cBtnClient -Font $fontSmall
    $btnMapOK.DialogResult = 'OK'
    $mapForm.Controls.Add($btnMapOK)
    $mapForm.AcceptButton = $btnMapOK

    $mapResult = $mapForm.ShowDialog()
    if ($mapResult -ne 'OK') { return }

    $persistent = $chkPersist.Checked
    $persistFlag = if ($persistent) { "/persistent:yes" } else { "/persistent:no" }
    $letterIdx = $cbDrive.SelectedIndex

    $mappedCount = 0
    for ($i = 0; $i -lt $clbShares.Items.Count; $i++) {
        if ($clbShares.GetItemChecked($i)) {
            $shareName = $shares[$i].Name
            $uncPath = "\\$($script:hostName)\$shareName"
            if ($letterIdx -lt $availableLetters.Count) {
                $letter = $availableLetters[$letterIdx]
                try {
                    net use "${letter}:" /delete /y 2>$null | Out-Null
                    $result = net use "${letter}:" "$uncPath" $persistFlag 2>&1
                    if ($LASTEXITCODE -ne 0 -and "$result" -match 'error') { throw $result }
                    Write-Log $log "Mapped ${letter}: -> $uncPath" "OK"
                    $letterIdx++
                    $mappedCount++
                } catch {
                    Write-Log $log "Failed to map ${letter}: to $uncPath - $_" "FAIL"
                }
            } else {
                Write-Log $log "No more drive letters available for $uncPath" "WARN"
            }
        }
    }

    Refresh-ClientStatus -LV $lvClient
    if ($mappedCount -gt 0) {
        [System.Windows.Forms.MessageBox]::Show("$mappedCount drive(s) mapped!", "Success", 'OK', 'Information')
    }
})

# ══════════════════════════════════════════════════════════════════════════════
# CLIENT — Connect Printers
# ══════════════════════════════════════════════════════════════════════════════
$btnConPrt.Add_Click({
    $log = $txtCliLog
    if (-not $script:hostName) {
        [System.Windows.Forms.MessageBox]::Show("Connect to a host first!", "Connect Printers", 'OK', 'Warning')
        return
    }

    Write-Log $log "Discovering printers on \\$($script:hostName)..." "WORK"
    [System.Windows.Forms.Application]::DoEvents()

    $printers = @()
    try {
        $wmiPrinters = Get-WmiObject -Class Win32_Printer -ComputerName $script:hostName -ErrorAction Stop |
            Where-Object { $_.Shared -eq $true }
        foreach ($p in $wmiPrinters) {
            $printers += [PSCustomObject]@{ Name = $p.Name; ShareName = $p.ShareName }
        }
    } catch {
        try {
            $netView = net view "\\$($script:hostName)" 2>&1
            $printerLines = $netView | Where-Object { $_ -match 'Print' }
            foreach ($line in $printerLines) {
                if ($line -match '^\s*(\S+)\s+Print') {
                    $printers += [PSCustomObject]@{ Name = $Matches[1]; ShareName = $Matches[1] }
                }
            }
        } catch { }
    }

    # Fallback to ShareInfo.txt
    if ($printers.Count -eq 0 -and $script:infoPrinters.Count -gt 0) {
        foreach ($pName in $script:infoPrinters) {
            $printers += [PSCustomObject]@{ Name = $pName; ShareName = $pName }
        }
        Write-Log $log "Using printer names from ShareInfo.txt" "INFO"
    }

    if ($printers.Count -eq 0) {
        $manualName = [Microsoft.VisualBasic.Interaction]::InputBox(
            "No shared printers found on \\$($script:hostName).`nEnter a printer share name manually (or leave blank to cancel):",
            "Manual Printer Name", "")
        if ([string]::IsNullOrWhiteSpace($manualName)) { return }
        $printers += [PSCustomObject]@{ Name = $manualName; ShareName = $manualName }
    }

    # Build picker form
    $cpForm = New-Object System.Windows.Forms.Form
    $cpForm.Text            = "Connect Printers"
    $cpForm.Size            = New-Object System.Drawing.Size(440, 350)
    $cpForm.StartPosition   = 'CenterParent'
    $cpForm.FormBorderStyle = 'FixedDialog'
    $cpForm.MaximizeBox     = $false
    $cpForm.MinimizeBox     = $false
    $cpForm.BackColor       = $cBg
    $cpForm.ForeColor       = $cText

    $lblCpPick = New-Object System.Windows.Forms.Label
    $lblCpPick.Text     = "Printers on \\$($script:hostName):"
    $lblCpPick.Location = New-Object System.Drawing.Point(15, 12)
    $lblCpPick.AutoSize = $true
    $cpForm.Controls.Add($lblCpPick)

    $clbPrt = New-Object System.Windows.Forms.CheckedListBox
    $clbPrt.Location  = New-Object System.Drawing.Point(15, 38)
    $clbPrt.Size      = New-Object System.Drawing.Size(390, 200)
    $clbPrt.BackColor = $cPanel
    $clbPrt.ForeColor = $cText
    $clbPrt.Font      = $fontSmall
    $clbPrt.BorderStyle = 'None'
    $clbPrt.CheckOnClick = $true
    foreach ($p in $printers) {
        $pName = if ($p.ShareName) { $p.ShareName } else { $p.Name }
        $clbPrt.Items.Add($pName, $true) | Out-Null
    }
    $cpForm.Controls.Add($clbPrt)

    $btnCpOK = New-StyledButton -Text "Connect Selected" -X 260 -Y 260 -W 150 -H 35 -BgColor $cBtnClient -Font $fontSmall
    $btnCpOK.DialogResult = 'OK'
    $cpForm.Controls.Add($btnCpOK)
    $cpForm.AcceptButton = $btnCpOK

    $cpResult = $cpForm.ShowDialog()
    if ($cpResult -ne 'OK') { return }

    $connectedCount = 0
    for ($i = 0; $i -lt $clbPrt.Items.Count; $i++) {
        if ($clbPrt.GetItemChecked($i)) {
            $pShare = if ($printers[$i].ShareName) { $printers[$i].ShareName } else { $printers[$i].Name }
            $printerPath = "\\$($script:hostName)\$pShare"
            try {
                Add-Printer -ConnectionName $printerPath -ErrorAction Stop
                Write-Log $log "Connected: $printerPath" "OK"
                $connectedCount++
            } catch {
                try {
                    rundll32 printui.dll,PrintUIEntry /in /n "$printerPath" 2>$null
                    Write-Log $log "Connected: $printerPath (via printui)" "OK"
                    $connectedCount++
                } catch {
                    Write-Log $log "Failed to add '$printerPath': $_" "FAIL"
                }
            }
        }
    }

    Refresh-ClientStatus -LV $lvClient
    if ($connectedCount -gt 0) {
        [System.Windows.Forms.MessageBox]::Show("$connectedCount printer(s) connected!", "Success", 'OK', 'Information')
    }
})

# ══════════════════════════════════════════════════════════════════════════════
# CLIENT — Disconnect
# ══════════════════════════════════════════════════════════════════════════════
$btnDiscon.Add_Click({
    $log = $txtCliLog

    # Gather items
    $mapped = @()
    try { $mapped = @(Get-WmiObject -Class Win32_MappedLogicalDisk -ErrorAction SilentlyContinue) } catch {}
    if ($mapped.Count -eq 0) {
        $netUseLines = net use 2>$null | Where-Object { $_ -match '\\\\' }
        foreach ($line in $netUseLines) {
            if ($line -match '([A-Z]:)\s+(\\\\[^\s]+)') {
                $mapped += [PSCustomObject]@{ DeviceID = $Matches[1]; ProviderName = $Matches[2] }
            }
        }
    }
    $netPrinters = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'Connection' })

    if ($mapped.Count -eq 0 -and $netPrinters.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Nothing to disconnect.", "Disconnect", 'OK', 'Information')
        return
    }

    # Build picker
    $dcForm = New-Object System.Windows.Forms.Form
    $dcForm.Text            = "Disconnect Drives && Printers"
    $dcForm.Size            = New-Object System.Drawing.Size(500, 380)
    $dcForm.StartPosition   = 'CenterParent'
    $dcForm.FormBorderStyle = 'FixedDialog'
    $dcForm.MaximizeBox     = $false
    $dcForm.MinimizeBox     = $false
    $dcForm.BackColor       = $cBg
    $dcForm.ForeColor       = $cText

    $lblDcPick = New-Object System.Windows.Forms.Label
    $lblDcPick.Text     = "Select items to disconnect:"
    $lblDcPick.Location = New-Object System.Drawing.Point(15, 12)
    $lblDcPick.AutoSize = $true
    $dcForm.Controls.Add($lblDcPick)

    $clbDc = New-Object System.Windows.Forms.CheckedListBox
    $clbDc.Location  = New-Object System.Drawing.Point(15, 38)
    $clbDc.Size      = New-Object System.Drawing.Size(450, 240)
    $clbDc.BackColor = $cPanel
    $clbDc.ForeColor = $cText
    $clbDc.Font      = $fontSmall
    $clbDc.BorderStyle = 'None'
    $clbDc.CheckOnClick = $true

    $dcItems = @()
    foreach ($d in $mapped) {
        $clbDc.Items.Add("[Drive] $($d.DeviceID) -> $($d.ProviderName)") | Out-Null
        $dcItems += @{ Type="Drive"; ID=$d.DeviceID }
    }
    foreach ($p in $netPrinters) {
        $clbDc.Items.Add("[Printer] $($p.Name)") | Out-Null
        $dcItems += @{ Type="Printer"; Name=$p.Name }
    }
    $dcForm.Controls.Add($clbDc)

    $btnDcOK = New-StyledButton -Text "Disconnect Selected" -X 310 -Y 295 -W 160 -H 35 -BgColor $cRed -Font $fontSmall
    $btnDcOK.DialogResult = 'OK'
    $dcForm.Controls.Add($btnDcOK)
    $dcForm.AcceptButton = $btnDcOK

    $dcResult = $dcForm.ShowDialog()
    if ($dcResult -ne 'OK') { return }

    $removedCount = 0
    for ($i = 0; $i -lt $clbDc.Items.Count; $i++) {
        if ($clbDc.GetItemChecked($i)) {
            $item = $dcItems[$i]
            if ($item.Type -eq "Drive") {
                net use $item.ID /delete /y 2>$null | Out-Null
                Write-Log $log "Disconnected: $($item.ID)" "OK"
                $removedCount++
            } elseif ($item.Type -eq "Printer") {
                Remove-Printer -Name $item.Name -ErrorAction SilentlyContinue
                Write-Log $log "Removed printer: $($item.Name)" "OK"
                $removedCount++
            }
        }
    }
    Refresh-ClientStatus -LV $lvClient
    if ($removedCount -gt 0) {
        [System.Windows.Forms.MessageBox]::Show("$removedCount item(s) disconnected.", "Done", 'OK', 'Information')
    }
})

# ══════════════════════════════════════════════════════════════════════════════
# CLIENT — View Status
# ══════════════════════════════════════════════════════════════════════════════
$btnViewCli.Add_Click({
    Refresh-ClientStatus -LV $lvClient
    $log = $txtCliLog
    $hostLabel = if ($script:hostName) { $script:hostName } else { "(not connected)" }
    $driveCount   = ($lvClient.Items | Where-Object { $_.Text -eq "Drive" }).Count
    $printerCount = ($lvClient.Items | Where-Object { $_.Text -eq "Printer" }).Count
    Write-Log $log "--- Connection Status ---" "INFO"
    Write-Log $log "Host: $hostLabel  |  Drives: $driveCount  |  Printers: $printerCount" "INFO"
    if ($script:hostName) {
        Write-Log $log "Quick access: open Explorer and type \\$($script:hostName)" "INFO"
    }
})

# ══════════════════════════════════════════════════════════════════════════════
# LOAD VisualBasic for InputBox
# ══════════════════════════════════════════════════════════════════════════════
Add-Type -AssemblyName Microsoft.VisualBasic

# ══════════════════════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════════════════════
Show-Panel 'Launch'
[System.Windows.Forms.Application]::Run($form)
