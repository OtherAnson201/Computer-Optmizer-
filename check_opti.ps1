$failed = [System.Collections.ArrayList]::new()
$ok     = [System.Collections.ArrayList]::new()
# record and print a passed check
function Pass($n)       { $script:ok.Add($n)|Out-Null; Write-Host "  [OK] $n" -ForegroundColor Green }
# record and print a failed check
function Fail($n,$e,$a) { $script:failed.Add([PSCustomObject]@{Check=$n;Expected=$e;Actual=$a})|Out-Null; Write-Host "  [FAIL] $n  expected=$e  actual=$a" -ForegroundColor Red }

Write-Host '--- TCP Port Range ---' -ForegroundColor Cyan
foreach ($proto in 'tcp','udp') {
    foreach ($ip in 'ipv4','ipv6') {
        $out = (netsh int $ip show dynamicport $proto) -join ' '
        if ($out -match 'Start Port\s*:\s*1025')     { Pass "$ip $proto start=1025" }    else { Fail "$ip $proto start"  '1025'  '' }
        if ($out -match 'Number of Ports\s*:\s*64511'){ Pass "$ip $proto ports=64511" }  else { Fail "$ip $proto ports" '64511' '' }
    }
}

Write-Host '--- TCP Registry (should be absent) ---' -ForegroundColor Cyan
$r = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
foreach ($n in @('TcpMaxDataRetransmissions','KeepAliveTime','KeepAliveInterval',
                  'InitialRtt','MaxFreeTcbs','MaxHashTableSize','NumTcbTablePartitions','TcpNumConnections')) {
    $v = (Get-ItemProperty $r -Name $n -EA SilentlyContinue).$n
    if ($null -eq $v) { Pass "Reg $n absent" } else { Fail "Reg $n" 'absent' $v }
}
$t13 = (Get-ItemProperty $r -Name Tcp1323Opts -EA SilentlyContinue).Tcp1323Opts
if ($null -eq $t13 -or $t13 -eq 0) { Pass 'Tcp1323Opts absent/0 (OK)' } else { Fail 'Tcp1323Opts' '0 or absent' $t13 }
$twd = (Get-ItemProperty $r -Name TcpTimedWaitDelay -EA SilentlyContinue).TcpTimedWaitDelay
if ($twd -eq 30) { Pass 'TcpTimedWaitDelay=30' } else { Fail 'TcpTimedWaitDelay' '30' $twd }

Write-Host '--- TCP Global ---' -ForegroundColor Cyan
$tcp = (netsh int tcp show global) -join "`n"
$checks = @(
    @('RSS',              'enabled',  'Receive-Side Scaling State\s*:\s*(\S+)'),
    @('Auto-Tuning',      'normal',   'Receive Window Auto-Tuning Level\s*:\s*(\S+)'),
    @('ECN',              'disabled', 'ECN Capability\s*:\s*(\S+)'),
    @('Timestamps',       'disabled|allowed', 'RFC 1323 Timestamps\s*:\s*(\S+)'),
    @('InitialRTO',       '1000',     'Initial RTO\s*:\s*(\S+)'),
    @('RSC',              'enabled',  'Receive Segment Coalescing State\s*:\s*(\S+)'),
    @('NonSackRtt',       'disabled', 'Non Sack Rtt Resiliency\s*:\s*(\S+)'),
    @('MaxSYNRetrans',    '4',        'Max SYN Retransmissions\s*:\s*(\S+)'),
    @('FastOpen',         'enabled',  'Fast Open\s*:\s*(\S+)'),
    @('FastOpenFallback', 'enabled',  'Fast Open Fallback\s*:\s*(\S+)'),
    @('HyStart',          'enabled',  'HyStart\s*:\s*(\S+)'),
    @('PRR',              'enabled',  'Proportional Rate Reduction\s*:\s*(\S+)'),
    @('PacingProfile',    'off',      'Pacing Profile\s*:\s*(\S+)')
)
foreach ($c in $checks) {
    if ($tcp -match $c[2]) {
        $val = $Matches[1].ToLower()
        if ($val -match "^($($c[1]))$") { Pass "TCP $($c[0])=$val" } else { Fail "TCP $($c[0])" $c[1] $val }
    } else { Fail "TCP $($c[0])" $c[1] 'not found' }
}

Write-Host '--- Registry / Multimedia ---' -ForegroundColor Cyan
$mm = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
$nti = (Get-ItemProperty $mm -Name NetworkThrottlingIndex -EA SilentlyContinue).NetworkThrottlingIndex
if ($nti -eq -1 -or $nti -eq 4294967295) { Pass 'NetworkThrottlingIndex=disabled' } else { Fail 'NetworkThrottlingIndex' '0xFFFFFFFF' $nti }
$sr = (Get-ItemProperty $mm -Name SystemResponsiveness -EA SilentlyContinue).SystemResponsiveness
if ($sr -eq 20) { Pass 'SystemResponsiveness=20' } else { Fail 'SystemResponsiveness' '20' $sr }

# ── WEBVIEW2 ──────────────────────────────────────────────────────────────────
Write-Host '--- WebView2 (HKLM should be absent) ---' -ForegroundColor Cyan
$wvL = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Edge\WebView2' -Name AdditionalBrowserArguments -EA SilentlyContinue).AdditionalBrowserArguments
if ($null -eq $wvL) { Pass 'WebView2 HKLM absent' } else { Fail 'WebView2 HKLM' 'absent' $wvL }

Write-Host '--- Memory ---' -ForegroundColor Cyan
$mma = Get-MMAgent -EA SilentlyContinue
if ($mma) {
    if (-not $mma.MemoryCompression) { Pass 'MemoryCompression disabled' } else { Fail 'MemoryCompression' 'Disabled' 'Enabled' }
    if (-not $mma.PageCombining)     { Pass 'PageCombining disabled' }      else { Fail 'PageCombining' 'Disabled' 'Enabled' }
} else { Fail 'MMAgent' 'available' 'not available' }

# ── NIC ───────────────────────────────────────────────────────────────────────
Write-Host '--- NIC ---' -ForegroundColor Cyan
foreach ($adp in (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })) {
    $an    = $adp.Name
    $props = Get-NetAdapterAdvancedProperty -Name $an -EA SilentlyContinue
    foreach ($c in @(
        @('Interrupt Moderation',      'Disabled'),
        @('Flow Control',              'Rx & Tx Enabled'),
        @('Energy-Efficient Ethernet', 'Disabled'),
        @('Green Ethernet',            'Disabled'),
        @('Power Saving Mode',         'Disabled'),
        @('Advanced EEE',              'Disabled'),
        @('Gigabit Lite',              'Disabled')
    )) {
        $x = $props | Where-Object { $_.DisplayName -eq $c[0] }
        if (-not $x) { continue }
        if ($x.DisplayValue -eq $c[1]) { Pass "$an $($c[0])=$($c[1])" } else { Fail "$an $($c[0])" $c[1] $x.DisplayValue }
    }
    foreach ($dn in @('Receive Buffers','Transmit Buffers')) {
        $x = $props | Where-Object { $_.DisplayName -eq $dn }
        if (-not $x) { continue }
        $maxV = $x.NumericParameterMaxValue
        if ($x.DisplayValue -eq "$maxV") { Pass "$an $dn=max($maxV)" } else { Fail "$an $dn" "max($maxV)" $x.DisplayValue }
    }
    $rs = Get-NetAdapterRss -Name $an -EA SilentlyContinue
    if ($rs) { if ($rs.Enabled) { Pass "$an RSS=enabled" } else { Fail "$an RSS" 'Enabled' 'Disabled' } }
}

Write-Host '--- Power + BCD ---' -ForegroundColor Cyan
$scheme = (powercfg /getactivescheme) -join ' '
if ($scheme -match '8c5e7fda|e9a42b02|SCHEME_MIN') { Pass 'Power plan High/Ultimate Perf' } else { Fail 'Power plan' 'High/Ultimate' $scheme }
$bcd = (bcdedit /enum '{current}') -join ' '
if ($bcd -match 'hypervisorlaunchtype\s+Off') { Pass 'BCD hypervisorlaunchtype=Off' } else { Fail 'BCD hypervisorlaunchtype' 'Off' 'not Off' }
if ($bcd -notmatch 'numproc\s+1') { Pass 'BCD numproc not limited' } else { Fail 'BCD numproc' 'absent' '1 (CPU limited!)' }

Write-Host '--- Desktop Heap ---' -ForegroundColor Cyan
$h = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems' -Name Windows -EA SilentlyContinue).Windows
$heapVal = if ($h -match 'SharedSection=([\d,]+)') { $Matches[1] } else { 'not found' }
if ($h -match 'SharedSection=1024,20480') { Pass "Desktop heap OK ($heapVal)" } else { Fail 'Desktop heap' '1024,20480,*' $heapVal }

# ── HOSTS ─────────────────────────────────────────────────────────────────────
Write-Host '--- Hosts ---' -ForegroundColor Cyan
$hf = [IO.File]::ReadAllText('C:\Windows\System32\drivers\etc\hosts')
if ($hf -notmatch 'farmsync\.cloud') { Pass 'hosts farmsync.cloud unblocked' } else { Fail 'hosts' 'clean' 'farmsync.cloud blocked' }

# ── SUMMARY ───────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host "=== PASSED $($ok.Count) ===" -ForegroundColor Green
if ($failed.Count -eq 0) {
    Write-Host 'All checks passed.' -ForegroundColor Green
} else {
    Write-Host "=== FAILED $($failed.Count) ===" -ForegroundColor Red
    $failed | Format-Table -AutoSize
}
Read-Host 'Press Enter to close'
