# Setting Up DVLS Linux Server on Ubuntu 22.04 with SQL Server

This guide describes how to fully set up **Devolutions Server (DVLS)** on **Ubuntu Server 22.04**, running inside **Hyper-V** (2GB RAM, 2 vCPUs).

## 1. Install Microsoft SQL Server

```bash
curl https://packages.microsoft.com/keys/microsoft.asc | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc
sudo add-apt-repository "$(wget -qO- https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/mssql-server-2022.list)"
sudo apt-get update -y
sudo apt-get install -y mssql-server
```

## 2. Install utilities

```bash
sudo apt install -y nano git
```

## 3. Set up a swap file (8 GB)

```bash
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## 4. Bypass SQL Server Memory Check

```bash
git clone https://github.com/awakecoding/mssql-memory-bypass
cd mssql-memory-bypass
sudo cp fake_meminfo.so /opt/mssql/lib/fake_meminfo.so
```

Create a systemd override:

```bash
sudo mkdir -p /etc/systemd/system/mssql-server.service.d

sudo tee /etc/systemd/system/mssql-server.service.d/override.conf > /dev/null <<EOF
[Service]
Environment="LD_PRELOAD=/opt/mssql/lib/fake_meminfo.so"
EOF
```

Run SQL Server setup:

```bash
sudo LD_PRELOAD='/opt/mssql/lib/fake_meminfo.so' MSSQL_PID='Express' MSSQL_SA_PASSWORD='SuperPass123!' /opt/mssql/bin/mssql-conf -n setup accept-eula
```

Reload and start SQL Server:

```bash
sudo systemctl daemon-reload
sudo systemctl restart mssql-server
systemctl status mssql-server
sudo systemctl enable mssql-server
```

## 5. Install PowerShell

```bash
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y powershell
```

Install Devolutions.PowerShell module:

```bash
sudo pwsh -Command 'Install-Module Devolutions.PowerShell -Scope AllUsers -Force'
```

## 6. Set up the DVLS User and Directory

```bash
sudo useradd -N dvls
sudo groupadd dvls
sudo usermod -a -G dvls dvls
sudo usermod -a -G dvls $(id -un)

sudo mkdir -p /opt/devolutions/dvls
sudo chown -R dvls:dvls /opt/devolutions/dvls
sudo chmod 555 /opt/devolutions/dvls
```

## 7. Download and Extract DVLS

```bash
curl -O https://cdn.devolutions.net/download/RDMS/DVLS.2025.1.5.0.linux-x64.tar.gz
sudo tar -xzf DVLS.2025.1.5.0.linux-x64.tar.gz -C /opt/devolutions/dvls --strip-components=1

sudo chmod 660 "/opt/devolutions/dvls/appsettings.json"
sudo chmod 770 "/opt/devolutions/dvls/App_Data"
```

## 8. Configure DVLS Using Devolutions.PowerShell

Start PowerShell as `dvls`:

```bash
sudo -u dvls pwsh -NoProfile -wd /opt/devolutions/dvls
```

Inside PowerShell:

```powershell
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
```

## 9. Create a systemd Service for DVLS

```bash
sudo tee /etc/systemd/system/dvls.service > /dev/null <<EOT
[Unit]
Description=DVLS

[Service]
Type=simple
Restart=always
RestartSec=10
User=dvls
ExecStart=/opt/devolutions/dvls/Devolutions.Server
WorkingDirectory=/opt/devolutions/dvls
KillSignal=SIGINT
SyslogIdentifier=dvls
Environment="SCHEDULER_EMBEDDED=true"

[Install]
WantedBy=multi-user.target
Alias=dvls.service
EOT

sudo systemctl daemon-reload
sudo systemctl start dvls
systemctl status dvls
sudo systemctl enable dvls
```

## 10. Done

DVLS Linux Server should now be up and running at:

**https://dvls.local:5000**

Edit the hosts file on your client machine to point "dvls.local" to the IP address of the server where DVLS is running.
