#!/bin/bash
echo "Starting prebuild..."
echo "Upgrading pip..."
pip install --upgrade pip
echo "Installing build tools..."
pip install wheel setuptools
echo "Installing cryptography dependencies..."
pip install cffi>=1.15.1
echo "Prebuild complete"