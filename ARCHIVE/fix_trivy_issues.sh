#!/bin/bash

# Update Debian packages to fix known vulnerabilities
echo "Updating system packages..."
sudo apt update
sudo apt upgrade -y

# Fix specific vulnerable packages by installing latest versions
# libarchive13t64 (affected version 3.7.4-3)
echo "Upgrading libarchive13t64..."
sudo apt install --only-upgrade libarchive13t64

# FFmpeg related packages with fix_deferred status
echo "Upgrading FFmpeg related packages..."
sudo apt install --only-upgrade libavcodec61 libavfilter10 libavformat61 libavutil59 libpostproc58 libswresample5 libswscale8

# BlueZ Bluetooth stack packages
echo "Upgrading BlueZ packages..."
sudo apt install --only-upgrade bluez bluez-obexd

# Check if pip is installed and upgrade relevant Python packages if applicable
if command -v pip3 &>/dev/null; then
    echo "Upgrading Python packages via pip..."
    pip3 install --upgrade pip
    # Add any specific Python package upgrades here if known
fi

# Check if gem is installed and upgrade Ruby gems if applicable
if command -v gem &>/dev/null; then
    echo "Upgrading Ruby gems..."
    gem update
fi

# Check if npm is installed and update global npm packages if applicable
if command -v npm &>/dev/null; then
    echo "Updating global npm packages..."
    npm update -g
fi

echo "Vulnerability fixes applied. Please verify the system's security status."