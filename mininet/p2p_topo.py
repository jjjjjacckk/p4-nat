from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from p4_mininet import P4Switch, P4Host

import argparse
from time import sleep

# set argument
parser = argparse.ArgumentParser(description='P2P Mininet')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable (path to simple_switch)',
                    type=str, action="store", required=True)
parser.add_argument('--thrift-port1', help='Thrift server port for table updates of switch_1',
                    type=int, action="store", default=9090)
parser.add_argument('--thrift-port2', help='Thrift server port for table updates of switch_2',
                    type=int, action="store", default=9091)
# parser.add_argument('--num-hosts', help='Number of hosts to connect to switch',
#                     type=int, action="store", default=2)
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=True)
# pcap = packet capture
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)
args = parser.parse_args()


class MyTopo(Topo):
    def __init__(self, sw_path, json_path, thrift_port1, thrift_port2, pcap_dump, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        # set switch 1
        switch_1 = self.addSwitch('s1',
                                sw_path = sw_path,
                                json_path = json_path,
                                thrift_port = thrift_port1,
                                pcap_dump = pcap_dump)
        cpu1 = self.addHost('cpu1',
                            ip = "10.0.0.10/24",
                            mac = '00:02:00:00:00:00')
        self.addLink(cpu1, switch_1)

        # set switch 2
        switch_2 = self.addSwitch('s2',
                                sw_path = sw_path,
                                json_path = json_path,
                                thrift_port = thrift_port2,
                                pcap_dump = pcap_dump)
        cpu2 = self.addHost('cpu2',
                            ip = "192.168.0.10/24",
                            mac = '00:04:00:00:00:00')
        self.addLink(cpu2, switch_2)

        # set server 
        server = self.addHost('server',
                            ip = '172.16.0.0',
                            mac = '00:10:00:00:00:00')
        self.addLink(server, switch_1)
        self.addLink(server, switch_2)

        # set indivisual hosts
        for h in xrange(2):
            host = self.addHost('h%d' % (h + 1),
                                ip = "10.0.%d.10/24" % (h + 1),
                                mac = '00:02:00:00:00:%02x' %(h + 1))
            self.addLink(host, switch_1)
        
        for h in xrange(2, 4):
            host = self.addHost('h%d' % (h + 1),
                                ip = "192.168.%d.10/24" % (h + 1),
                                mac = '00:04:00:00:00:%02x' %(h + 1))
            self.addLink(host, switch_2)

def main():
    mode = args.mode

    topo = MyTopo(args.behavioral_exe,
                    args.json,
                    args.thrift_port1,
                    args.thrift_port2,
                    args.pcap_dump)

    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  controller = None)
    net.start()

    # set ARP
    sw_mac = ["00:02:00:00:00:01", "00:02:00:00:00:02", 
              "00:04:00:00:00:03", "00:04:00:00:00:04",
              "00:10:00:00:00:00"]

    sw_addr = ["10.0.1.10", "10.0.2.10", 
               "192.168.3.10", "192.168.4.10",
               "172.16.0.0"]

    for n in xrange(5):
        if n == 4:
            h = net.get('server')
        else:
            h = net.get('h%d' % (n + 1))

        if mode == "l2":
            h.setDefaultRoute("dev eth0")
        else:
            h.setARP(sw_addr[n], sw_mac[n])
            h.setDefaultRoute("dev eth0 via %s" % sw_addr[n])
    

    for n in xrange(5):
        if n == 4:
            h = net.get('server')
        else:
            h = net.get('h%d' % (n + 1))
        h.describe()

    sleep(1)

    print ("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()