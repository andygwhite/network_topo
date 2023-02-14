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
import matplotlib.pyplot as plt
from cluster_load_balancer import SimpleSwitch13

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
                self.run_experiment()
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
        """Provides user with a menu to choose what experiment to run"""
        while True:
            print('Please select an option')
            print('\tq: Return')
            print('\t1: First Stage Experiment')
            print('\t2: Second Stage Experiment')
            try:
                choice = input()
            except EOFError:
                return
            if choice == 'q':
                return
            elif choice == '1':
                self.stage_one_exp()
            elif choice == '2':
                self.stage_two_exp()

    def clear_experiment_logs(self):
        """Helper function to clear all logs by executing commands on c0"""
        for log in ["./ryu.log", "./experiment.csv"]:
            self.net.get('c0').cmd("truncate -s 0 ./ryu.log")

    def stage_one_exp(self):
        """Build a confusion matrix for a given PCAP validation file"""
        results = dict()
        for exp, fname in self.cfg["first_stage_experiment_files"].items():
            # Clear the ryu log
            self.clear_experiment_logs()
            print(f"Running {exp} experiment from {fname}")
            results[exp] = dict()
            if not os.path.exists(fname):
                print("ERROR: Could not find file", fname)
                continue
            p = self.hosts[0].cmd([
                'python3', './packet_generator.py', fname])
            for prediction_result in ["cpu", "network", "memory"]:
                p = subprocess.Popen(
                    f'grep "PREDICTION: {prediction_result}" ./ryu.log | wc -l',
                    shell=True, stdout=subprocess.PIPE)
                results[exp][prediction_result] = int(p.communicate()[0])
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
        return

    def stage_two_exp(self):
        """Report average latency, bandwidth, utilization, etc.
        for each server"""
        # Clear the ryu log
        # with open(RYU_LOGFILE, 'w') as f:
        #     f.write('')
        self.clear_experiment_logs()
        print(f"Running 2nd stage test")
        # Record the number of requests sent to each server by counting Ryu log
        # Count all hosts minus the pgen host
        results = {}
        p = self.hosts[0].cmd(
            ['python3', './packet_generator.py', self.cfg["second_stage_experiment_file"]])
        for i in range(1, len(self.hosts)):
            p = subprocess.Popen(
                    f'grep "Sending to server 10\.0\.0\.{i}" ./ryu.log | wc -l',
                    shell=True, stdout=subprocess.PIPE)
            results[i] = int(p.communicate()[0])
        # Clean up latency & bandwidth info from cfg file
        latencies = {i: int(self.cfg["host_latency"][str(i)].replace("ms",""))
                     for i in range(1, len(self.hosts))}
        bandwidths = {i: self.cfg["host_bandwidth"][str(i)]
                      for i in range(1, len(self.hosts))}
        total_latency = sum([results[i] * latencies[i] for i in range(1, len(self.hosts))])
        total_bandwidth = sum([results[i] * bandwidths[i] for i in range(1, len(self.hosts))])
        total_packets = sum(list(results.values()))
        print("Average latency:", total_latency/total_packets)
        print("Average bandwidth:", total_bandwidth/total_packets)

    def quit(self):
        """Necessary to let Mininet clean itself for next run"""
        print('Shutting Down Topology')
        self.net.stop()
        exit()

if __name__ == "__main__":
    topo = ClusterTopo()

