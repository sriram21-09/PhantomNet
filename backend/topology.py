from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

class PhantomTopo(Topo):
    "PhantomNet 5-Node Star Topology"

    def build(self):
        # 1. Create the Central Switch
        # The 's1' switch acts as the hub for our star topology
        switch = self.addSwitch('s1')

        # 2. Define Node Specifications (Role, IP, MAC)
        # We assign static MAC addresses to make debugging easier (00:00:00:00:00:0X)
        hosts_config = [
            {"name": "h1", "ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "desc": "Coordinator (DB/Dash)"},
            {"name": "h2", "ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "desc": "Honeypot-SSH"},
            {"name": "h3", "ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "desc": "Honeypot-HTTP"},
            {"name": "h4", "ip": "10.0.0.4", "mac": "00:00:00:00:00:04", "desc": "Honeypot-FTP"},
            {"name": "h5", "ip": "10.0.0.5", "mac": "00:00:00:00:00:05", "desc": "Attacker-PC"}
        ]

        # 3. Create Hosts and Links
        for host_conf in hosts_config:
            # Add the host to the topology
            node = self.addHost(
                host_conf["name"], 
                ip=host_conf["ip"], 
                mac=host_conf["mac"]
            )
            
            # Create the Link with Realistic Constraints
            # bw=100Mbps, delay=10ms (Simulating LAN latency)
            self.addLink(node, switch, cls=TCLink, bw=100, delay='10ms')

def run_network():
    "Boot up the network simulation"
    topo = PhantomTopo()
    # We use a RemoteController so we can eventually hook this up to an SDN controller (like Ryu/ODL)
    net = Mininet(topo=topo, link=TCLink, controller=None)
    
    # Add a basic controller to make routing work automatically for now
    net.addController('c0', controller=Controller)

    print("🚀 PhantomNet Simulation Started")
    print("   Subnet: 10.0.0.0/24")
    print("   Nodes:  h1(Coord), h2(SSH), h3(HTTP), h4(FTP), h5(Attacker)")
    
    net.start()
    
    # Drop the user into the Mininet Command Line Interface (CLI)
    CLI(net)
    
    print("🛑 Stopping Network...")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_network()