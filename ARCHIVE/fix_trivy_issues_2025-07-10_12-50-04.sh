#!/bin/bash

# Update Debian packages to fix known vulnerabilities
sudo apt update

# Upgrade affected system packages to their latest secure versions
sudo apt upgrade -y libarchive13t64 libpython3.13 libpython3.13-dev libpython3.13-stdlib libpython3.13-minimal libavcodec61 libavfilter10 libavformat61 libavutil59 libpostproc58 libswresample5 libswscale8 libxml2 libsndfile1 bluez bluez-obexd busybox gir1.2-gst-plugins-bad-1.0 libgstreamer-plugins-bad1.0-0

# Upgrade Linux kernel headers to mitigate kernel vulnerabilities
sudo apt install --only-upgrade linux-headers-6.12.33+deb13-amd64

# Upgrade firmware and related packages if applicable
# (Add commands here if specific firmware packages are affected)

# Upgrade Python packages via pip with --break-system-packages for Debian compatibility
pip3 install --break-system-packages --upgrade pip
pip3 install --break-system-packages --upgrade python3

# If you have any Node.js packages, ensure npm is installed and then update
if command -v npm &> /dev/null; then
    npm update -g
fi

# Clean up unused packages and cache
sudo apt autoremove -y
sudo apt clean

echo "System packages have been upgraded to mitigate vulnerabilities. Please review specific package updates for completeness."