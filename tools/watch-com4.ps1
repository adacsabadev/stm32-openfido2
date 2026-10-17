$ErrorActionPreference = 'Stop'
$captureDirectory = Join-Path $PSScriptRoot '..\logs'
New-Item -ItemType Directory -Force -Path $captureDirectory | Out-Null
$capturePath = Join-Path $captureDirectory ('com4-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
$interactive = -not [Console]::IsInputRedirected
$commandLine = [System.Text.StringBuilder]::new()
function Write-Capture([string]$Message) {
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') + '] ' + $Message
    Add-Content -LiteralPath $capturePath -Value $line -Encoding utf8
    Write-Output $line
}
Write-Capture ('Capture started: ' + $capturePath)
if ($interactive) { Write-Host 'Type CDC commands here; press Enter to send. Ctrl+C exits.'; Write-Host -NoNewline 'com4> ' }
while ($true) {
    $port = $null
    try {
        $port = [System.IO.Ports.SerialPort]::new('COM4', 115200, [System.IO.Ports.Parity]::None, 8, [System.IO.Ports.StopBits]::One)
        $port.DtrEnable = $true
        $port.Open()
        Write-Capture 'CONNECTED COM4, 115200 8N1, DTR enabled'
        while ($port.IsOpen) {
            $chunk = $port.ReadExisting()
            if ($chunk.Length -gt 0) { Write-Capture $chunk }
            if ($interactive -and [Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::Enter) {
                    $port.Write($commandLine.ToString() + "`r`n")
                    $commandLine.Clear() | Out-Null
                    Write-Host ''
                    Write-Host -NoNewline 'com4> '
                } elseif ($key.Key -eq [ConsoleKey]::Backspace) {
                    if ($commandLine.Length -gt 0) {
                        $commandLine.Length--
                        Write-Host -NoNewline "`b `b"
                    }
                } elseif (-not [char]::IsControl($key.KeyChar)) {
                    [void]$commandLine.Append($key.KeyChar)
                    $typed = $commandLine.ToString()
                    if ($typed.StartsWith('pin set ', [System.StringComparison]::OrdinalIgnoreCase)) {
                        Write-Host -NoNewline '*'
                    } elseif ($typed.StartsWith('pin change ', [System.StringComparison]::OrdinalIgnoreCase)) {
                        Write-Host -NoNewline '*'
                    } else {
                        Write-Host -NoNewline $key.KeyChar
                    }
                }
            }
            Start-Sleep -Milliseconds 100
        }
        Write-Capture 'Port closed; reconnecting'
    } catch {
        Write-Capture ('Disconnected/unavailable; retrying: ' + $_.Exception.Message)
    } finally {
        if ($null -ne $port) {
            if ($port.IsOpen) { $port.Close() }
            $port.Dispose()
        }
    }
    Start-Sleep -Seconds 1
}
