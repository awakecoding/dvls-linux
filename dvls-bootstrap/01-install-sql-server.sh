#!/bin/bash
set -e

curl https://packages.microsoft.com/keys/microsoft.asc | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc
sudo add-apt-repository -y "$(wget -qO- https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/mssql-server-2022.list)"
sudo apt-get update -y
sudo apt-get install -y mssql-server

git clone https://github.com/awakecoding/mssql-memory-bypass
cd mssql-memory-bypass
sudo cp fake_meminfo.so /opt/mssql/lib/fake_meminfo.so

sudo mkdir -p /etc/systemd/system/mssql-server.service.d
sudo tee /etc/systemd/system/mssql-server.service.d/override.conf > /dev/null <<EOF
[Service]
Environment="LD_PRELOAD=/opt/mssql/lib/fake_meminfo.so"
EOF

sudo LD_PRELOAD='/opt/mssql/lib/fake_meminfo.so' MSSQL_PID='Express' MSSQL_SA_PASSWORD='SuperPass123!' /opt/mssql/bin/mssql-conf -n setup accept-eula
sudo systemctl daemon-reload
sudo systemctl restart mssql-server
sudo systemctl enable mssql-server
