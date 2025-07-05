#!/bin/bash

# Quick fix for the gfortran package issue
echo "Fixing package installation..."

# Update package list
sudo apt update

# Install the remaining packages without gfortran
sudo apt install -y \
    libatlas-base-dev \
    libhdf5-dev \
    libhdf5-serial-dev \
    libgstreamer1.0-0 \
    libgstreamer-plugins-base1.0-0 \
    libgtk-3-0 \
    libavcodec-dev \
    libavformat-dev \
    libswscale-dev \
    libv4l-dev \
    libxvidcore-dev \
    libx264-dev \
    libjpeg-dev \
    libpng-dev \
    libtiff-dev \
    libtesseract-dev \
    tesseract-ocr \
    tesseract-ocr-eng \
    git \
    curl \
    wget \
    unzip \
    build-essential \
    cmake \
    pkg-config

echo "Package installation completed!"
echo "You can now continue with the ChastiPi installation."
