Import-Module Devolutions.PowerShell -ErrorAction Stop

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

# Generate certificate only if using HTTPS
if ($WebScheme -eq 'https') {
    Write-Host "Generating self-signed TLS certificate for '$Hostname'..."

    $CertFolder = Join-Path $DVLSPath "App_Data"
    $TlsCertificateFile = Join-Path $CertFolder "server.pem"
    $TlsPrivateKeyFile = Join-Path $CertFolder "server.key"
    $Arguments = @(
        "req", "-x509", "-nodes",
        "-newkey", "rsa:2048",
        "-keyout", $TlsPrivateKeyFile,
        "-out", $TlsCertificateFile,
        "-subj", "/CN=$Hostname",
        "-addext", "subjectAltName=DNS:$Hostname",
        "-days", "1825"
    )

    $Output = & openssl @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed:`n$Output"
    }
}

# Build appsettings.json
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

# Patch appsettings.json with certificate if using HTTPS
if ($WebScheme -eq 'https') {
    $AppSettingsPath = Join-Path $DVLSPath 'appsettings.json'
    $AppSettingsJson = Get-Content -Path $AppSettingsPath | ConvertFrom-Json -Depth 10

    if ($TlsCertificateFile -and $TlsPrivateKeyFile) {
        $AppSettingsJson.Kestrel.Endpoints.Http | Add-Member -MemberType NoteProperty -Name 'Certificate' -Value @{
            'Path' = $TlsCertificateFile
            'KeyPath' = $TlsPrivateKeyFile
        }
    }

    Write-Host $($AppSettingsJson | ConvertTo-Json -Depth 10)

    $AppSettingsJson | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath
}

& "$Env:DVLS_EXECUTABLE_PATH"
[System.Environment]::ExitCode = $LASTEXITCODE
