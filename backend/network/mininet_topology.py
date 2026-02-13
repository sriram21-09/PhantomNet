import os
import time
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.topo import Topo

class PhantomTopo(Topo):
    "PhantomNet 5-Node Star Topology"

    def build(self):
        # 1. Create the Central Switch
        info( '*** Adding Switch\n' )
        switch = self.addSwitch('s1')

        # 2. Define Node Specifications
        # H1 = Coordinator (Database + Dashboard)
        # H2-H4 = Honeypots (Traps)
        # H5 = Attacker (Kali Simulator)
        hosts_config = [
            {"name": "h1", "ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "desc": "Coordinator"},
            {"name": "h2", "ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "desc": "SSH-Honeypot"},
            {"name": "h3", "ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "desc": "HTTP-Honeypot"},
            {"name": "h4", "ip": "10.0.0.4", "mac": "00:00:00:00:00:04", "desc": "FTP-Honeypot"},
            {"name": "h5", "ip": "10.0.0.5", "mac": "00:00:00:00:00:05", "desc": "Attacker"}
        ]

        # 3. Create Hosts and Links
        info( '*** Adding Hosts & Links\n' )
        for host_conf in hosts_config:
            # Add Host
            node = self.addHost(
                host_conf["name"], 
                ip=host_conf["ip"], 
                mac=host_conf["mac"]
            )
            
            # Add Link with Constraints (100Mbps, 10ms Latency)
            # This simulates a real corporate LAN environment
            self.addLink(node, switch, cls=TCLink, bw=100, delay='10ms')

def run_simulation():
    "Boot up the PhantomNet Network"
    topo = PhantomTopo()
    
    # Initialize Mininet with Traffic Control Links (TCLink)
    net = Mininet(topo=topo, link=TCLink, controller=Controller)
    
    info( '*** Starting Network\n' )
    net.start()
    
    info( '*** Verifying Connectivity (Ping All)\n' )
    # This checks if all nodes can talk to each other
    net.pingAll()

    print("\n🚀 PhantomNet Simulation Running")
    print("   Coordinator (H1): 10.0.0.1")
    print("   Attacker    (H5): 10.0.0.5")
    print("   (Type 'exit' to stop)\n")

    # Drop user into the Command Line Interface
    CLI(net)
    
    info( '*** Stopping Network\n' )
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    # Check for root privileges (Mininet needs root)
    if os.geteuid() != 0:
        print("❌ Error: Mininet must be run as root (sudo python mininet_topology.py)")
        exit(1)
    
    run_simulation()
