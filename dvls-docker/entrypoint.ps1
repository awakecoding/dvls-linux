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
$DVLSAccessUri = "$ExternalWebScheme`://$Hostname`:$ExternalWebPort/"

$DVLSPath         = $Env:DVLS_PATH            ?? "/opt/devolutions/dvls"
$AdminUsername    = $Env:DVLS_ADMIN_USERNAME  ?? "dvls-admin"
$AdminPassword    = $Env:DVLS_ADMIN_PASSWORD  ?? "dvls-admin"
$AdminEmail       = $Env:DVLS_ADMIN_EMAIL     ?? "admin@$Hostname"
$DBHost           = $Env:DVLS_DB_HOST         ?? "localhost"
$DBName           = $Env:DVLS_DB_NAME         ?? "dvls"
$DBUser           = $Env:DVLS_DB_USER         ?? "sa"
$DBPassword       = $Env:DVLS_DB_PASS         ?? "SuperPass123!"

$DVLSInit = try { [bool]::Parse($Env:DVLS_INIT) } catch { $false }
$EnableTelemetry = try { [bool]::Parse($Env:DVLS_TELEMETRY) } catch { $true }

$AppDataPath = Join-Path $DVLSPath "App_Data"

$TlsCertificateFile = $null
if ($Env:TLS_CERTIFICATE_B64) {
    try {
        $TlsCertificateFile = Join-Path $AppDataPath "server.pem"
        [IO.File]::WriteAllBytes($TlsCertificateFile, [Convert]::FromBase64String($Env:TLS_CERTIFICATE_B64))
    } catch {
        throw "Failed to decode TLS_CERTIFICATE_B64"
    }
}

$TlsPrivateKeyFile = $null
if ($Env:TLS_PRIVATE_KEY_B64) {
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
    "DatabaseHost"           = $DBHost
    "DatabaseName"           = $DBName
    "DatabaseUserName"       = $DBUser
    "DatabasePassword"       = $DBPassword
    "ServerName"             = $Hostname
    "AccessUri"              = $DVLSAccessUri
    "HttpListenerUri"        = $DVLSListenUri
    "DPSPath"                = $DVLSPath
    "UseEncryptedconnection" = $false
    "TrustServerCertificate" = $false
    "EnableTelemetry"        = $EnableTelemetry
    "DisableEncryptConfig"   = $true
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

Write-Host "Launching Devolutions Server: $DVLSAccessUri"

& "$Env:DVLS_EXECUTABLE_PATH"
[System.Environment]::ExitCode = $LASTEXITCODE
