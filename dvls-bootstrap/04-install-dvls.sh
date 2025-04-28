#!/bin/bash
set -e

curl -O https://cdn.devolutions.net/download/RDMS/DVLS.2025.1.5.0.linux-x64.tar.gz
sudo tar -xzf DVLS.2025.1.5.0.linux-x64.tar.gz -C /opt/devolutions/dvls --strip-components=1

sudo chmod 660 "/opt/devolutions/dvls/appsettings.json"
sudo chmod 770 "/opt/devolutions/dvls/App_Data"
