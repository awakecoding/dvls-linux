#!/bin/bash
set -e

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
sudo systemctl enable dvls
