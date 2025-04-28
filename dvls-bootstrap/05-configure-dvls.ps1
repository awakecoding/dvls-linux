Import-Module -Name 'Devolutions.PowerShell'

$DVLSPath = "/opt/devolutions/dvls"
$DVLSURI  = "https://dvls.local:5000/"

$DVLSAdminUsername = 'dvls-admin'
$DVLSAdminPassword = 'dvls-admin'
$DVLSAdminEmail    = 'admin@dvls.local'

$CertFolder = Join-Path -Path $DVLSPath -ChildPath 'App_Data'
if (-Not (Test-Path $CertFolder)) {
    New-Item -ItemType Directory -Path $CertFolder | Out-Null
}

$CertKeyPath = Join-Path -Path $CertFolder -ChildPath 'cert.key'
$CertCrtPath = Join-Path -Path $CertFolder -ChildPath 'cert.crt'
$CertPfxPath = Join-Path -Path $CertFolder -ChildPath 'cert.pfx'
$Hostname = "dvls.local"

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes `
    -keyout $CertKeyPath `
    -out $CertCrtPath `
    -subj "/CN=$Hostname" `
    -addext "subjectAltName=DNS:$Hostname"

openssl pkcs12 -export `
    -out $CertPfxPath `
    -inkey $CertKeyPath `
    -in $CertCrtPath `
    -passout pass:

$Params = @{
    "DatabaseHost"           = "localhost"
    "DatabaseName"           = "dvls"
    "DatabaseUserName"       = "sa"
    "DatabasePassword"       = "SuperPass123!"
    "ServerName"             = "dvls"
    "AccessUri"              = $DVLSURI
    "HttpListenerUri"        = $DVLSURI
    "DPSPath"                = $DVLSPath
    "UseEncryptedconnection" = $False
    "TrustServerCertificate" = $False
    "EnableTelemetry"        = $False
    "DisableEncryptConfig"   = $True
}

$Configuration = New-DPSInstallConfiguration @Params
New-DPSAppsettings -Configuration $Configuration

$Settings = Get-DPSAppSettings -ApplicationPath $DVLSPath

New-DPSDatabase -ConnectionString $Settings.ConnectionStrings.LocalSqlServer
Update-DPSDatabase -ConnectionString $Settings.ConnectionStrings.LocalSqlServer -InstallationPath $DVLSPath
New-DPSDataSourceSettings -ConnectionString $Settings.ConnectionStrings.LocalSqlServer

New-DPSEncryptConfiguration -ApplicationPath $DVLSPath
New-DPSDatabaseAppSettings -Configuration $Configuration

New-DPSAdministrator -ConnectionString $Settings.ConnectionStrings.LocalSqlServer -Name $DVLSAdminUsername -Password $DVLSAdminPassword -Email $DVLSAdminEmail

$JSON = Get-Content -Path (Join-Path -Path $DVLSPath -ChildPath 'appsettings.json') | ConvertFrom-Json -Depth 10
$JSON.Kestrel.Endpoints.Http | Add-Member -MemberType NoteProperty -Name 'Certificate' -Value @{
    'Path'     = $CertPfxPath
    'Password' = ''
}
$JSON | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path -Path $DVLSPath -ChildPath 'appsettings.json')
