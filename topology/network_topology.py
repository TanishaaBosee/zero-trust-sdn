"""
network_topology.py - Mininet Network Topology for Zero Trust SDN
==================================================================
This script creates the network topology for testing the
Zero Trust SDN framework.

Topology:
- 1 OpenFlow Switch (OVS)
- 4 Hosts (h1, h2, h3, h4)
- 1 RYU Controller (external)

Host Roles:
- h1: Legitimate Monitoring Application
- h2: Legitimate Admin Application
- h3: Malicious Application (for testing)
- h4: Normal Network User

The topology is designed to test:
1. Legitimate application access (should be allowed)
2. Malicious application access (should be blocked)
3. Zero Trust verification pipeline
4. Policy enforcement
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

import time
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ZeroTrustTopology(Topo):
    """
    Zero Trust SDN Network Topology
    
    Topology:
    
        [RYU Controller with Zero Trust]
                    |
                [OpenFlow Switch]
               /        |        \
              /         |         \
        [h1: Monitor] [h2: Admin] [h3: Malicious] [h4: User]
        
    Hosts:
    - h1: Legitimate Monitoring Application (trusted)
    - h2: Legitimate Admin Application (trusted)
    - h3: Malicious Application (untrusted - for testing)
    - h4: Normal Network User
    """

    def build(self):
        # Add switches
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        
        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        
        # Connect hosts to switch
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


def create_network():
    """
    Create and start the Mininet network with Zero Trust SDN controller.
    
    This function:
    1. Creates the topology
    2. Connects to the RYU controller
    3. Starts the network
    4. Provides CLI access for testing
    """
    from mininet.net import Mininet
    from mininet.cli import CLI
    from mininet.log import info, error
    
    info("*** Creating Zero Trust SDN Topology\n")
    topo = ZeroTrustTopology()
    
    info("*** Starting network with RYU controller\n")
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSSwitch,
        build=True,
        autoSetMacs=True
    )
    
    info("*** Starting network\n")
    net.start()
    
    info("*** Network is running\n")
    info("*** Hosts:\n")
    for host in net.hosts:
        info(f"    {host.name} - IP: {host.IP()} - MAC: {host.MAC()}\n")
    
    info("*** Testing connectivity\n")
    net.pingAll()
    
    info("*** Opening CLI for testing\n")
    CLI(net)
    
    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    create_network()
