#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def create_phantomnet_topology():
    info("*** Creating PhantomNet Mininet Topology\n")

    net = Mininet(
        controller=None,          # 🚫 No controller (required for Ubuntu 24.04)
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
        build=False
    )

    # Single core switch
    s1 = net.addSwitch("s1")

    # PhantomNet Nodes
    h1 = net.addHost("h1", ip="10.0.0.10/24")   # Traffic Generator
    h2 = net.addHost("h2", ip="10.0.1.20/24")   # Benign Client
    h3 = net.addHost("h3", ip="10.0.2.30/24")   # SMTP Honeypot
    h4 = net.addHost("h4", ip="10.0.2.31/24")   # SSH Honeypot
    h5 = net.addHost("h5", ip="10.0.3.40/24")   # Attacker Simulation

    # Links
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(h5, s1)

    net.build()
    net.start()

    info("*** PhantomNet topology running\n")
    CLI(net)

    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    create_phantomnet_topology()

