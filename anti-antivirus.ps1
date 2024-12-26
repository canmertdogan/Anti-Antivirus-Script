# Script to remove traces of antivirus software
# Run as Administrator

# Log file path
$logFile = "$env:TEMP\AntivirusCleanup.log"

# List of common antivirus software
$antivirusList = @("Kaspersky", "Avira", "Webroot", "F-Secure", "McAfee", "Norton", "Avast", "AVG", "Bitdefender", "Sophos", "TrendMicro")

# Function to log messages
function Log-Message {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$timestamp] $message"
    Write-Host $message
}

# Function to stop services
function Stop-AntivirusServices {
    Log-Message "Stopping antivirus services..."
    foreach ($av in $antivirusList) {
        Get-Service | Where-Object { $_.DisplayName -like "*$av*" } | ForEach-Object {
            Log-Message "Stopping service: $($_.DisplayName)"
            Stop-Service -InputObject $_ -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to terminate processes
function Stop-AntivirusProcesses {
    Log-Message "Terminating antivirus processes..."
    foreach ($av in $antivirusList) {
        Get-Process | Where-Object { $_.ProcessName -like "*$av*" } | ForEach-Object {
            Log-Message "Terminating process: $($_.ProcessName)"
            Stop-Process -InputObject $_ -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to uninstall software
function Uninstall-AntivirusSoftware {
    Log-Message "Uninstalling antivirus software..."
    foreach ($av in $antivirusList) {
        $installed = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$av*" }
        if ($installed) {
            foreach ($app in $installed) {
                Log-Message "Uninstalling: $($app.Name)"
                $app.Uninstall() | Out-Null
            }
        }
    }
}

# Function to remove directories
function Remove-AntivirusDirectories {
    Log-Message "Removing antivirus directories..."
    $commonPaths = @("C:\Program Files\", "C:\Program Files (x86)\", "C:\ProgramData\", "C:\Users\*\AppData\Local\", "C:\Users\*\AppData\Roaming\")
    foreach ($av in $antivirusList) {
        foreach ($path in $commonPaths) {
            Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$av*" } | ForEach-Object {
                Log-Message "Removing directory: $($_.FullName)"
                Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# Function to clean up registry entries
function Remove-AntivirusRegistryEntries {
    Log-Message "Cleaning up antivirus registry entries..."
    $registryPaths = @(
        "HKLM:\SOFTWARE\",
        "HKCU:\SOFTWARE\",
        "HKLM:\SYSTEM\CurrentControlSet\Services\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
        "HKLM:\SOFTWARE\Classes\CLSID\",
        "HKLM:\SOFTWARE\Classes\Installer\Products\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers\",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows\AppInit_DLLs\",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Network\",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\"
    )
    foreach ($av in $antivirusList) {
        foreach ($path in $registryPaths) {
            Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSPath -like "*$av*" } | ForEach-Object {
                Log-Message "Removing registry key: $($_.PSPath)"
                Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# Function to remove scheduled tasks
function Remove-AntivirusScheduledTasks {
    Log-Message "Removing antivirus scheduled tasks..."
    foreach ($av in $antivirusList) {
        Get-ScheduledTask | Where-Object { $_.TaskName -like "*$av*" } | ForEach-Object {
            Log-Message "Removing scheduled task: $($_.TaskName)"
            Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

# Function to remove startup entries
function Remove-AntivirusStartupEntries {
    Log-Message "Removing antivirus startup entries..."
    foreach ($av in $antivirusList) {
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | ForEach-Object {
            if ($_.PSObject.Properties.Value -like "*$av*") {
                Log-Message "Removing startup entry: $($_.PSPath)"
                Remove-ItemProperty -Path $_.PSPath -Name $_.PSObject.Properties.Name -ErrorAction SilentlyContinue
            }
        }
    }
}

# Function to clean Windows Defender exclusions
function Clean-WindowsDefenderExclusions {
    Log-Message "Cleaning Windows Defender exclusions..."
    $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
    foreach ($exclusion in $exclusions) {
        if ($exclusion -like "*$av*") {
            Log-Message "Removing Windows Defender exclusion: $exclusion"
            Remove-MpPreference -ExclusionPath $exclusion -ErrorAction SilentlyContinue
        }
    }
}

# Execute functions
Log-Message "Starting antivirus cleanup..."
Stop-AntivirusServices
Stop-AntivirusProcesses
Uninstall-AntivirusSoftware
Remove-AntivirusDirectories
Remove-AntivirusRegistryEntries
Remove-AntivirusScheduledTasks
Remove-AntivirusStartupEntries
Clean-WindowsDefenderExclusions
Log-Message "Antivirus cleanup completed. Log saved to $logFile"
