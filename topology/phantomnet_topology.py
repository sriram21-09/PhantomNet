import os
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class PhantomNetTopo(Topo):
    """
    3-Layer Topology for PhantomNet SD-N Setup
    - Core Layer: Central routing
    - Distribution Layer: Network segmentation
    - Access Layer: End hosts and honeypots
    """
    def build(self):
        # ----------------------------------------------------
        # 1. Add Switches (3-Layer Architecture)
        # ----------------------------------------------------
        # Core Switch
        s_core = self.addSwitch('s1', dpid='0000000000000001')
        
        # Distribution Switches
        s_dist1 = self.addSwitch('s2', dpid='0000000000000002') # Serves external/internal
        s_dist2 = self.addSwitch('s3', dpid='0000000000000003') # Serves honeypots and monitor
        
        # Access Switches
        s_acc1 = self.addSwitch('s4', dpid='0000000000000004') # External
        s_acc2 = self.addSwitch('s5', dpid='0000000000000005') # Internal
        s_acc3 = self.addSwitch('s6', dpid='0000000000000006') # Honeypots
        s_acc4 = self.addSwitch('s7', dpid='0000000000000007') # Monitoring
        
        # Connect Core to Distribution
        self.addLink(s_core, s_dist1, bw=1000)
        self.addLink(s_core, s_dist2, bw=1000)
        
        # Connect Distribution to Access
        self.addLink(s_dist1, s_acc1, bw=500)
        self.addLink(s_dist1, s_acc2, bw=500)
        self.addLink(s_dist2, s_acc3, bw=500)
        self.addLink(s_dist2, s_acc4, bw=500)
        
        # ----------------------------------------------------
        # 2. Add Hosts (PhantomNet Roles)
        # ----------------------------------------------------
        # h1: External Attacker
        h1 = self.addHost('h1', ip='10.0.0.10/24', mac='00:00:00:00:00:01')
        self.addLink(h1, s_acc1, bw=100, delay='10ms')

        # h2: Internal User
        h2 = self.addHost('h2', ip='10.0.1.20/24', mac='00:00:00:00:00:02')
        self.addLink(h2, s_acc2, bw=100, delay='1ms')

        # h3: SMTP Honeypot
        h3 = self.addHost('h3', ip='10.0.2.30/24', mac='00:00:00:00:00:03')
        self.addLink(h3, s_acc3, bw=100, delay='1ms')

        # h4: SSH Honeypot
        h4 = self.addHost('h4', ip='10.0.2.31/24', mac='00:00:00:00:00:04')
        self.addLink(h4, s_acc3, bw=100, delay='1ms')

        # h5: Backend & SOC Node (Monitor)
        h5 = self.addHost('h5', ip='10.0.3.40/24', mac='00:00:00:00:00:05')
        self.addLink(h5, s_acc4, bw=100, delay='1ms')

def add_traffic_mirror():
    """
    Implements Port Mirroring using OVS.
    Mirrors traffic from s3 (Honeypot Distribution Switch) to s7 (Monitoring Switch)
    where the monitoring node (h5) is attached.
    """
    info('*** Configuring Port Mirroring on s3 to forward traffic to the Monitor node (h5)...\n')
    
    # Identify ports (Port 1 might go to core, Port 2 to acc3(honeypots), Port 3 to acc4(monitor))
    # We will mirror traffic crossing s3 to the port connecting s3 to s4(monitor access switch)
    
    # Clean previous mirrors
    os.system('ovs-vsctl -- --id=@m create mirror name=m0 -- add bridge s3 mirrors @m')
    
    # We want to select all traffic on s3, or specific ports, and output to the port leading to the monitor.
    # To robustly mirror all traffic on an OVS switch:
    cmd_mirror = (
        'ovs-vsctl '
        '-- set Bridge s3 mirrors=@m '
        '-- --id=@s3_port2 get Port s3-eth2 ' # Port leading towards honeypots (s_acc3)
        '-- --id=@s3_port3 get Port s3-eth3 ' # Port leading towards monitor (s_acc4)
        '-- --id=@m create Mirror name=span1 select-all=true output-port=@s3_port3'
    )
    # Applying port mirror
    info(f'*** Executing OVS mirror command:\n{cmd_mirror}\n')
    os.system(cmd_mirror)
    info('*** Port Mirroring active.\n')

def run_topology():
    setLogLevel('info')
    
    info('*** Creating 3-Layer SD-N Network\n')
    topo = PhantomNetTopo()
    
    info('*** Starting network\n')
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSKernelSwitch, link=TCLink)
    net.start()
    
    # Apply Traffic Mirroring logic
    add_traffic_mirror()
    
    info('*** Running CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    run_topology()
