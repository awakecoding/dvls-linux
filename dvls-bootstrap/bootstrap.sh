#!/bin/bash
set -e

./00-prepare-system.sh
./01-install-sql-server.sh
./02-install-powershell.sh
./03-setup-dvls-user.sh
./04-install-dvls.sh

echo "Now switching to dvls user for PowerShell configuration..."
sudo -u dvls pwsh -NoProfile -File ./05-configure-dvls.ps1

./06-create-dvls-service.sh
