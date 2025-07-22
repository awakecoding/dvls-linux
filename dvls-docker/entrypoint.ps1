Import-Module Devolutions.PowerShell -ErrorAction Stop

# Defaults from environment
$DVLSPath         = $Env:DVLS_PATH            ?? "/opt/devolutions/dvls"
$Hostname         = $Env:DVLS_HOSTNAME        ?? "localhost"
$Scheme           = $Env:DVLS_SCHEME          ?? "https"
$Port             = $Env:DVLS_PORT            ?? 5000
$DVLSURI          = "$Scheme`://$Hostname`:$Port/"
$AdminUsername    = $Env:DVLS_ADMIN_USERNAME  ?? "dvls-admin"
$AdminPassword    = $Env:DVLS_ADMIN_PASSWORD  ?? "dvls-admin"
$AdminEmail       = $Env:DVLS_ADMIN_EMAIL     ?? "admin@$Hostname"
$DBHost           = $Env:DVLS_DB_HOST         ?? "localhost"
$DBName           = $Env:DVLS_DB_NAME         ?? "dvls"
$DBUser           = $Env:DVLS_DB_USER         ?? "sa"
$DBPassword       = $Env:DVLS_DB_PASS         ?? "SuperPass123!"
$EnableTelemetry  = [bool]($Env:DVLS_TELEMETRY ?? "false")

# Generate certificate only if using HTTPS
if ($Scheme -eq 'https') {
    Write-Host "Generating self-signed certificate for scheme https..."

    $CertFolder = Join-Path $DVLSPath "App_Data"
    $CertKey    = Join-Path $CertFolder "cert.key"
    $CertCrt    = Join-Path $CertFolder "cert.crt"
    $CertPfx    = Join-Path $CertFolder "cert.pfx"

    if (-not (Test-Path $CertFolder)) {
        New-Item -ItemType Directory -Path $CertFolder | Out-Null
    }

    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes `
        -keyout $CertKey `
        -out $CertCrt `
        -subj "/CN=$Hostname" `
        -addext "subjectAltName=DNS:$Hostname"

    openssl pkcs12 -export `
        -out $CertPfx `
        -inkey $CertKey `
        -in $CertCrt `
        -passout pass:
}

# Build appsettings.json
$InstallParams = @{
    "DatabaseHost"           = $DBHost
    "DatabaseName"           = $DBName
    "DatabaseUserName"       = $DBUser
    "DatabasePassword"       = $DBPassword
    "ServerName"             = $Hostname
    "AccessUri"              = $DVLSURI
    "HttpListenerUri"        = $DVLSURI
    "DPSPath"                = $DVLSPath
    "UseEncryptedconnection" = $false
    "TrustServerCertificate" = $false
    "EnableTelemetry"        = $EnableTelemetry
    "DisableEncryptConfig"   = $true
}

$Configuration = New-DPSInstallConfiguration @InstallParams
New-DPSAppsettings -Configuration $Configuration
$Settings = Get-DPSAppSettings -ApplicationPath $DVLSPath

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

# Patch appsettings.json with certificate if using HTTPS
if ($Scheme -eq 'https') {
    $AppSettingsPath = Join-Path $DVLSPath 'appsettings.json'
    $AppSettingsJson = Get-Content -Path $AppSettingsPath | ConvertFrom-Json -Depth 10

    $AppSettingsJson.Kestrel.Endpoints.Http | Add-Member -MemberType NoteProperty -Name 'Certificate' -Value @{
        'Path'     = Join-Path $DVLSPath "App_Data/cert.pfx"
        'Password' = ''
    }

    $AppSettingsJson | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath
}

# Launch DVLS
& "$Env:DVLS_EXECUTABLE_PATH"
[System.Environment]::ExitCode = $LASTEXITCODE
