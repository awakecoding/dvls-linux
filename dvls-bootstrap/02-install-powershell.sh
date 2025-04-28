#!/bin/bash
set -e

wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb

sudo apt-get update
sudo apt-get install -y powershell

sudo pwsh -Command 'Install-Module Devolutions.PowerShell -Scope AllUsers -Force'
