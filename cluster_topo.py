from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.util import irange
from mininet.link import TCLink
import pandas as pd
import json
import sys
import subprocess
import os

# Where to read/write experiment results
RYU_LOGFILE = './ryu.log'
# TODO: Add Logging!

class ClusterTopo( Topo ):
    """Class to manage the custom topology for this project.
    builds off of a simple single topo
    This script will handle generating traffic by
    sending commands to each server to run custom scripts."""
    def build( self, k=2, **_opts ):
        "k: number of hosts"
        self.k = k
        switch = self.addSwitch( 's1' )
        packet_generator = self.addHost('pgen')
        self.addLink(packet_generator, switch)
        for h in irange( 1, k ):
            host = self.addHost( 'h%s' % h )
            print(f"Setting bw={self.cfg['host_bandwidth'][f'{h}']}, delay={self.cfg['host_latency'][f'{h}']}")
            self.addLink(switch, host, bw=self.cfg["host_bandwidth"][f"{h}"], delay=self.cfg["host_latency"][f"{h}"])

    def __init__(self, cfg_filename='./topo_cluster_cfg.json'):
        """Wrapper for single topo init.
        Allows for specifying number of servers"""
        with open(cfg_filename, 'r') as f:
            self.cfg = json.load(f)
        # Initialize the number of hosts for each cluster
        k = int(self.cfg["num_hosts_per_cluster"]) * 3
        super().__init__(k=k)
        self.net = Mininet(topo=self, controller=RemoteController, link=TCLink)
        self.net.start()
        # Reassign controller to remote controller
        print("Topo Started Successfully")
        self.hosts = []
        # First host must be the packet generator
        self.hosts.append(self.net.get('pgen'))
        for i in range(1, k + 1):
            self.hosts.append(self.net.get(f'h{i}'))
        print("Attempting to set MTU for host machine to max packet size")
        for i in range(1,  k + 1):
            p = subprocess.Popen(f"sudo ifconfig s1-eth{i} mtu 65535", shell=True, stdout=subprocess.PIPE)
            if p.communicate()[1] is not None:
                print(f"[WARNING]: Failed to change MTU size on s1-eth{i}. Packets must not exceed 1500 bytes")
                break
        for i, host in enumerate(self.hosts):
            host.cmd(f"sudo ifconfig h{i+1}-eth0 mtu 65535")
        else:
            print("MTU Changed Successfully")
        choice = None
        while True:
            print('Please select an option')
            print('\tq: Quit Topology')
            print('\t1: Open CLI')
            print('\t2: Generate traffic')
            print('\t3: Open xterms for all machines')
            print('\t4: Run experiment')
            try:
                choice = input()
            except EOFError:
                self.quit()
            if choice == 'q':
                self.quit()
            elif choice == '1':
                CLI(self.net)
            elif choice == '2':
                self.generate_traffic()
            elif choice == '3':
                CLI(self.net, stdin=sys.stdin, script="./open_xterms.sh")
            elif choice == '4':
                results = self.run_experiment()
                print(pd.DataFrame.from_dict(results).to_markdown())
                total_count = 0
                total_correct = 0
                for exp in ["cpu", "memory", "network"]:
                    for label in ["cpu", "memory", "network"]:
                        total_count += results[exp][label]
                        if exp == label:
                            total_correct += results[exp][label]
                print("Correct:", total_correct)
                print("Total count:", total_count)
                print(f"Total Accuracy: {100*total_correct/total_count}%")
            else:
                print(choice, 'is not a valid option')

    def generate_traffic(self, pcap_file=None):
        """Generates traffic and listens on target machines"""
        if not pcap_file:
            pcap_file = self.cfg["default_pcap_file"]
        p = self.hosts[0].popen([
                'python3', './packet_generator.py', self.cfg["default_pcap_file"]])
        # return p.returncode

    def run_experiment(self):
        """Generates traffic from each of the labeled PCAP files,
        uses ryu logfile to count results"""
        results = dict()
        for exp, fname in self.cfg["experiment_files"].items():
            # Clear the ryu log
            with open(RYU_LOGFILE, 'w') as f:
                f.write('')
            print(f"Running {exp} experiment from {fname}")
            results[exp] = dict()
            if not os.path.exists(fname):
                print("ERROR: Could not find file", fname)
                continue
            p = self.hosts[0].cmd([
                'python3', './packet_generator.py', fname])
            for prediction_result in ["cpu", "network", "memory"]:
                p = subprocess.Popen(f'grep "PREDICTION: {prediction_result}" ./ryu.log | wc -l', shell=True, stdout=subprocess.PIPE)
                results[exp][prediction_result] = int(p.communicate()[0])
        return results

    # def read_experiment_results(self):
    #     """Uses GREP instead of readlines (performance optimization)
    #     to count the predictions made by the controller."""
    #     ret = []
    #     if not os.path.exists('./ryu.log'):
    #         print("Error: Could not find ryu log!")
    #         return False
    #     for label in ["cpu", "memory", "network"]:
    #         # TODO: Remove shell=True
    #         p = subprocess.Popen(f'grep "PREDICTION: {label}" ./ryu.log | wc -l', shell=True, stdout=subprocess.PIPE)
    #         ret.append(int(p.communicate()[0]))
    #     return tuple(ret)

    def quit(self):
        """Necessary to let Mininet clean itself for next run"""
        print('Shutting Down Topology')
        self.net.stop()
        exit()

if __name__ == "__main__":
    topo = ClusterTopo()

