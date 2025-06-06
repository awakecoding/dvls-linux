#!/bin/bash
set -e

sudo apt update
sudo apt install -y nano git wget curl software-properties-common apt-transport-https ca-certificates

sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
