from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.topo import SingleSwitchTopo
import json
import sys
import subprocess

# TODO: Add Logging!

class SmartSwitchTopo(SingleSwitchTopo):
    """Class to manage the custom topology for this project.
    builds off of a simple single topo with k=10
    Hosts 1 and 2 act as the target servers,
    Hosts 3 to 10 act as normal traffic generators.
    This script will handle generating traffic by
    sending commands to each server to run custom scripts.
    It will also keep tabs on the tcpdump from servers h1 and h2."""
    def __init__(self, cfg_filename='./topo_cfg.json'):
        """Wrapper for single topo init.
        Allows for specifying number of servers"""
        with open(cfg_filename, 'r') as f:
            self.cfg = json.load(f)
        super().__init__(k=self.cfg["num_hosts"])
        self.net = Mininet(topo=self, controller=RemoteController)
        self.net.start()
        # Reassign controller to remote controller
        print("Topo Started Successfully")
        self.hosts = []
        for i in range(1, self.cfg["num_hosts"] + 1):
            self.hosts.append(self.net.get(f'h{i}'))
        # print(self.hosts[1].cmd(['ping', '-c', '1', '10.0.0.2']))
        choice = None
        while True:
            print('Please select an option')
            print('\tq: Quit Topology')
            print('\t1: Open CLI')
            print('\t2: Generate traffic')
            print('\t3: Open xterms for all machines')
            try:
                choice = input()
            except EOFError:
                self.quit()
            if choice == 'q':
                self.quit()
            if choice == '1':
                CLI(self.net)
            if choice == '2':
                self.generate_traffic()
            if choice == '3':
                CLI(self.net, stdin=sys.stdin, script="./open_xterms.sh")
            else:
                print(choice, 'is not a valid option')

    def generate_traffic(self):
        """Generates traffic and listens on target machines"""
        p = self.hosts[3].popen([
                'python3', './scapy_scripts/packet_generator.py'])
        print(p.returncode)

    def quit(self):
        print('Shutting Down Topology')
        self.net.stop()
        exit()

if __name__ == "__main__":
    topo = SmartSwitchTopo()

