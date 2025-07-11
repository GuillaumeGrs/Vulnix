#!/bin/bash

# Update Debian packages to fix vulnerabilities
sudo apt update

# Upgrade affected packages to latest secure versions
sudo apt upgrade -y libarchive13t64 libavcodec61 libavfilter10 libavformat61 libavutil59 libpostproc58 libswresample5 libswscale8 bluez bluez-obexd libbluetooth3 busybox libsndfile1 linux-headers-6.12.33+deb13-amd64 linux-headers-6.12.33+deb13-common

# Fix kernel vulnerabilities by updating kernel packages
sudo apt full-upgrade -y

# Optional: Remove deprecated or fix-deferred packages if no longer needed
# sudo apt autoremove -y

# Check if pip is installed and upgrade relevant Python packages if applicable
if command -v pip3 &>/dev/null; then
    pip3 install --upgrade ffmpeg-python
fi

# Check if gem is installed and update Ruby gems if applicable
if command -v gem &>/dev/null; then
    gem update
fi

# Check if npm is installed and update global npm packages if applicable
if command -v npm &>/dev/null; then
    npm update -g
fi

echo "Vulnerability fixes applied successfully."