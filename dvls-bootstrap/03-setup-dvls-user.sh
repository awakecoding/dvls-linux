#!/bin/bash
set -e

sudo useradd -N dvls
sudo groupadd dvls
sudo usermod -a -G dvls dvls
sudo usermod -a -G dvls $(id -un)

sudo mkdir -p /opt/devolutions/dvls
sudo chown -R dvls:dvls /opt/devolutions/dvls
sudo chmod 555 /opt/devolutions/dvls
