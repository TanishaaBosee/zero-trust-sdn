#!/bin/bash
# install_dependencies.sh - Setup Script for Zero Trust SDN Framework
# =====================================================================
# Installs all dependencies for the Zero Trust SDN project.
#
# Prerequisites:
#   - Ubuntu 20.04/22.04 LTS (or a VM with these)
#   - Python 3.8+
#   - sudo privileges
#
# Installs:
#   1. Mininet          - network emulator
#   2. RYU Controller   - SDN controller
#   3. Open vSwitch     - OpenFlow switch
#   4. Python packages  - requests, matplotlib, psutil, networkx
#   5. Network tools    - iperf3, tcpdump, wireshark
#
# Run:  sudo bash setup/install_dependencies.sh

echo "============================================"
echo "Zero Trust SDN - Dependency Installation"
echo "============================================"

echo "[STEP 1] Updating package list..."
sudo apt-get update

echo "[STEP 2] Installing Mininet..."
sudo apt-get install -y mininet

echo "[STEP 3] Installing RYU Controller..."
sudo apt-get install -y python3-pip python3-dev
sudo pip3 install ryu

echo "[STEP 4] Installing Open vSwitch..."
sudo apt-get install -y openvswitch-switch openvswitch-common

echo "[STEP 5] Installing Python dependencies..."
sudo pip3 install requests numpy matplotlib psutil networkx

echo "[STEP 6] Installing network testing tools..."
sudo apt-get install -y net-tools iperf3 tcpdump wireshark

echo ""
echo "============================================"
echo "All dependencies installed successfully!"
echo "============================================"
echo ""
echo "Next steps:"
echo "1. Baseline controller: sudo ryu-manager controller/basic_controller.py"
echo "2. Zero Trust controller: sudo ryu-manager controller/ryu_controller.py"
echo "3. Network: sudo python3 topology/network_topology.py"
echo "4. App clients: python3 apps/http_app_client.py --app monitor"
echo "5. Attacks: python3 apps/http_app_client.py --attack replay"
echo "6. Offline tests: python3 tests/run_all_tests.py"
echo "7. Performance: python3 tests/test_performance.py"