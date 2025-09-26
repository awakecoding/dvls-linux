$ErrorActionPreference = 'Stop'
Import-Module Devolutions.PowerShell

$Hostname = 'localhost'
$WebScheme = 'http'

if ($Env:WEB_SCHEME) {
    $WebScheme = $Env:WEB_SCHEME
}

$ExternalWebScheme = $WebScheme

if ($Env:EXTERNAL_WEB_SCHEME) {
    $ExternalWebScheme = $Env:EXTERNAL_WEB_SCHEME
}

if (Test-Path Env:WEB_PORT) {
    $WebPort = $Env:WEB_PORT
}
if (Test-Path Env:PORT) {
    $WebPort = $Env:PORT
}

$ExternalWebPort = $WebPort

if (Test-Path Env:EXTERNAL_WEB_PORT) {
    $ExternalWebPort = $Env:EXTERNAL_WEB_PORT
}

if (Test-Path Env:HOSTNAME) {
    $Hostname = $Env:HOSTNAME
}
if (Test-Path Env:WEBSITE_HOSTNAME) {
    $Hostname = $Env:WEBSITE_HOSTNAME

    if (Test-Path Env:WEBSITE_INSTANCE_ID) {
        # Azure Web App always uses HTTPS on port 443 externally
        $ExternalWebScheme = 'https'
        $ExternalWebPort = 443
    }
}

$DVLSListenUri = "$WebScheme`://$Hostname`:$WebPort/"

if (($ExternalWebScheme -eq 'https' -and $ExternalWebPort -eq 443) -or
    ($ExternalWebScheme -eq 'http' -and $ExternalWebPort -eq 80)) {
    $DVLSAccessUri = "$ExternalWebScheme`://$Hostname/"
} else {
    $DVLSAccessUri = "$ExternalWebScheme`://$Hostname`:$ExternalWebPort/"
}

$DVLSPath         = $Env:DVLS_PATH            ?? "/opt/devolutions/dvls"
$AdminUsername    = $Env:DVLS_ADMIN_USERNAME  ?? "dvls-admin"
$AdminPassword    = $Env:DVLS_ADMIN_PASSWORD  ?? "dvls-admin"
$AdminEmail       = $Env:DVLS_ADMIN_EMAIL     ?? "admin@$Hostname"

# Load from environment: prefer DATABASE_*, also check AZURE_SQL_* which is used by Azure Web App
$DatabaseHost     = $Env:DATABASE_HOST     ?? $Env:AZURE_SQL_HOST
$DatabaseName     = $Env:DATABASE_NAME     ?? $Env:AZURE_SQL_DATABASE
$DatabaseUsername = $Env:DATABASE_USERNAME ?? $Env:AZURE_SQL_USERNAME
$DatabasePassword = $Env:DATABASE_PASSWORD ?? $Env:AZURE_SQL_PASSWORD
$DatabasePort     = $Env:DATABASE_PORT     ?? $Env:AZURE_SQL_PORT ?? "1433"

# Throw if any required value is missing
if ([string]::IsNullOrEmpty($DatabaseHost))     { throw "DATABASE_HOST or AZURE_SQL_HOST is required." }
if ([string]::IsNullOrEmpty($DatabaseName))     { throw "DATABASE_NAME or AZURE_SQL_DATABASE is required." }
if ([string]::IsNullOrEmpty($DatabaseUsername)) { throw "DATABASE_USERNAME or AZURE_SQL_USERNAME is required." }
if ([string]::IsNullOrEmpty($DatabasePassword)) { throw "DATABASE_PASSWORD or AZURE_SQL_PASSWORD is required." }

# Normalize host with port if needed
if ($DatabasePort -ne "1433" -and -not $DatabaseHost.Contains(',')) {
    $DatabaseHost = "$DatabaseHost,$DatabasePort"
}

$DVLSInit = try { [bool]::Parse($Env:DVLS_INIT) } catch { $false }
$EnableTelemetry = try { [bool]::Parse($Env:DVLS_TELEMETRY) } catch { $true }

$AppDataPath = Join-Path $DVLSPath "App_Data"

$TlsCertificateFile = $null
if ($Env:TLS_CERTIFICATE_FILE -and (Test-Path $Env:TLS_CERTIFICATE_FILE)) {
    # Use certificate file path directly from environment (e.g., k8s mounted secret)
    $TlsCertificateFile = $Env:TLS_CERTIFICATE_FILE
} elseif ($Env:TLS_CERTIFICATE_B64) {
    try {
        $TlsCertificateFile = Join-Path $AppDataPath "server.pem"
        [IO.File]::WriteAllBytes($TlsCertificateFile, [Convert]::FromBase64String($Env:TLS_CERTIFICATE_B64))
    } catch {
        throw "Failed to decode TLS_CERTIFICATE_B64"
    }
}

$TlsPrivateKeyFile = $null
if ($Env:TLS_PRIVATE_KEY_FILE -and (Test-Path $Env:TLS_PRIVATE_KEY_FILE)) {
    # Use private key file path directly from environment (e.g., k8s mounted secret)
    $TlsPrivateKeyFile = $Env:TLS_PRIVATE_KEY_FILE
} elseif ($Env:TLS_PRIVATE_KEY_B64) {
    try {
        $TlsPrivateKeyFile = Join-Path $AppDataPath "server.key"
        [IO.File]::WriteAllBytes($TlsPrivateKeyFile, [Convert]::FromBase64String($Env:TLS_PRIVATE_KEY_B64))
    } catch {
        throw "Failed to decode TLS_PRIVATE_KEY_B64"
    }
}

# Generate certificate only if using HTTPS
if ($WebScheme -eq 'https' -and
    [string]::IsNullOrEmpty($TlsCertificateFile) -and
    [string]::IsNullOrEmpty($TlsPrivateKeyFile)) {
    Write-Host "Generating self-signed TLS certificate for '$Hostname'..."

    $TlsCertificateFile = Join-Path $AppDataPath "server.pem"
    $TlsPrivateKeyFile = Join-Path $AppDataPath "server.key"
    $Arguments = @(
        "req", "-x509", "-nodes",
        "-newkey", "rsa:2048",
        "-keyout", $TlsPrivateKeyFile,
        "-out", $TlsCertificateFile,
        "-subj", "/CN=$Hostname",
        "-addext", "subjectAltName=DNS:$Hostname",
        "-addext", "extendedKeyUsage = serverAuth",
        "-days", "1825"
    )

    $Output = & openssl @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed:`n$Output"
    }
}

if ($Env:DVLS_ENCRYPTION_CONFIG_B64) {
    try {
        $EncryptionConfigFile = Join-Path $AppDataPath "encryption.config"
        [IO.File]::WriteAllBytes($EncryptionConfigFile, [Convert]::FromBase64String($Env:DVLS_ENCRYPTION_CONFIG_B64))
    } catch {
        throw "Failed to decode DVLS_ENCRYPTION_CONFIG_B64"
    }
}

$InstallParams = @{
    "DatabaseHost"           = $DatabaseHost
    "DatabaseName"           = $DatabaseName
    "DatabaseUserName"       = $DatabaseUsername
    "DatabasePassword"       = $DatabasePassword
    "ServerName"             = $Hostname
    "AccessUri"              = $DVLSAccessUri
    "HttpListenerUri"        = $DVLSListenUri
    "DPSPath"                = $DVLSPath
    "UseEncryptedconnection" = $false
    "TrustServerCertificate" = $false
    "EnableTelemetry"        = $EnableTelemetry
    "DisableEncryptConfig"   = $true
}

foreach ($key in $InstallParams.Keys) {
    $value = $InstallParams[$key]
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace($value.ToString())) {
        throw "Install configuration parameter '$key' is present but its value is null or empty."
    }
}

$Configuration = New-DPSInstallConfiguration @InstallParams
New-DPSAppsettings -Configuration $Configuration
$Settings = Get-DPSAppSettings -ApplicationPath $DVLSPath

if ($DVLSInit) {
    Write-Host "Initializing Devolutions Server..."

    # Initialize and migrate database
    New-DPSDatabase -ConnectionString $Settings.ConnectionStrings.LocalSqlServer
    Update-DPSDatabase -ConnectionString $Settings.ConnectionStrings.LocalSqlServer -InstallationPath $DVLSPath
    New-DPSDataSourceSettings -ConnectionString $Settings.ConnectionStrings.LocalSqlServer
    New-DPSEncryptConfiguration -ApplicationPath $DVLSPath
    New-DPSDatabaseAppSettings -Configuration $Configuration

    # Create admin user
    New-DPSAdministrator `
        -ConnectionString $Settings.ConnectionStrings.LocalSqlServer `
        -Name     $AdminUsername `
        -Password $AdminPassword `
        -Email    $AdminEmail   
}

# Update appsettings.json with certificate if using HTTPS
if ($WebScheme -eq 'https') {
    $AppSettingsPath = Join-Path $DVLSPath 'appsettings.json'
    $AppSettingsJson = Get-Content -Path $AppSettingsPath | ConvertFrom-Json -Depth 10

    if ($TlsCertificateFile -and $TlsPrivateKeyFile) {
        $AppSettingsJson.Kestrel.Endpoints.Http | Add-Member -MemberType NoteProperty -Name 'Certificate' -Value @{
            'Path' = $TlsCertificateFile
            'KeyPath' = $TlsPrivateKeyFile
        }
    }

    $AppSettingsJson | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath
}

$SshEnabled = try { [bool]::Parse($Env:SSH_ENABLED) } catch { $false }

if ((Test-Path Env:WEBSITE_INSTANCE_ID) -and (-Not (Test-Path Env:SSH_ENABLED))) {
    $SshEnabled = $true # Launch SSH server by default in Azure Web App
}

if ($SshEnabled) {
    $SshPort = if ($Env:SSH_PORT) { $Env:SSH_PORT } else { "2222" }
    $SshPassword = if ($Env:SSH_PASSWORD) { $Env:SSH_PASSWORD } else { "Docker!" }

    # Set root password
    bash -c "echo 'root:$SshPassword' | chpasswd"

    # Create SSH directory
    New-Item -ItemType Directory -Force -Path "/var/run/sshd" | Out-Null

    # Generate SSH config
    @"
Port $SshPort
ListenAddress 0.0.0.0
LoginGraceTime 180
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding yes
Ciphers aes128-cbc,3des-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr
MACs hmac-sha1,hmac-sha1-96
StrictModes yes
SyslogFacility DAEMON
Subsystem sftp internal-sftp
"@ | Out-File -FilePath "/etc/ssh/sshd_config" -Encoding ASCII

    # Start SSH daemon
    Start-Process -FilePath "/usr/sbin/sshd" -ArgumentList "-D", "-p", $SshPort -PassThru | Out-Null
    Write-Host "SSH daemon started on port $SshPort"
}

Write-Host "Launching Devolutions Server: $DVLSAccessUri"

& "$Env:DVLS_EXECUTABLE_PATH"
[System.Environment]::ExitCode = $LASTEXITCODE
