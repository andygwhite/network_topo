from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.topo import SingleSwitchTopo
import json
import sys
import subprocess
import os

# Where to read/write experiment results
RYU_LOGFILE = './ryu.log'
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
            print('\t4: Run experiment')
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
            if choice == '4':
                print(self.run_experiment())
            else:
                print(choice, 'is not a valid option')

    def generate_traffic(self, pcap_file=None):
        """Generates traffic and listens on target machines"""
        if not pcap_file:
            pcap_file = self.cfg["default_pcap_file"]
        p = self.hosts[3].popen([
                'python3', './packet_generator.py', self.cfg["default_pcap_file"]])
        # return p.returncode

    def run_experiment(self):
        """Generates traffic from each of the labeled PCAP files"""
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
            p = self.hosts[3].cmd([
                'python3', './packet_generator.py', fname, '-d1'])
            for prediction_result in ["cpu", "network", "memory"]:
                p = subprocess.Popen(f'grep "PREDICTION: {prediction_result}" ./ryu.log | wc -l', shell=True, stdout=subprocess.PIPE)
                results[exp][prediction_result] = int(p.communicate()[0])
        return results

    def read_experiment_results(self):
        """Uses GREP instead of readlines (performance optimization)
        to count the predictions made by the controller."""
        ret = []
        if not os.path.exists('./ryu.log'):
            print("Error: Could not find ryu log!")
            return False
        for label in ["cpu", "memory", "network"]:
            # TODO: Remove shell=True
            p = subprocess.Popen(f'grep "PREDICTION: {label}" ./ryu.log | wc -l', shell=True, stdout=subprocess.PIPE)
            ret.append(int(p.communicate()[0]))
        return tuple(ret)

    def quit(self):
        print('Shutting Down Topology')
        self.net.stop()
        exit()

if __name__ == "__main__":
    topo = SmartSwitchTopo()

