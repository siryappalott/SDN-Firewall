from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_network():
    net = Mininet(switch=OVSSwitch, controller=RemoteController)

    # Add a remote controller (your Ryu app)
    c0 = net.addController('c0', ip='127.0.0.1', port=6653)

    # Add switches
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')

    # Add hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')
    # Link everything
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(s1, s2)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_network()
