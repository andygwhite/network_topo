import csv
import multiprocessing
import random
import time
from mininet.net import Mininet
from mininet.node import RemoteController
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
from scapy.all import IP, IPOption, send, PcapReader, rdpcap


# Where to read/write experiment results
RYU_LOGFILE = './ryu.log'
# TODO: Add Logging!


class PacketGenerator:
    """General class to manage loading pcap files and sending via scapy.
    The class will generate a dict of Scapy packet_lists for each of the loaded
    pcap files for experiments.
    pcap_files: a dict used to load all necessary pcap files for experiments.
                The keys in this dict will be used as the keys for the loaded
                pcap dicts.
                The values are directory locations pointing to the given pcap
                file
    max_count_per_file: An integer limiting the number of packets to load per
                        pcap file."""
    def __init__(self, pcap_files, max_count_per_file=-1):
        self.packet_lists = {}
        for key, file in pcap_files.items():
            if not os.path.exists(file):
                raise FileNotFoundError(f"Could not find PCAP file {file}")   
            self.packet_lists[key] = rdpcap(file, count=max_count_per_file)

    def send_packets(self, packet_list_key):
        """Sends all packets from a loaded pcap file
        packet_list_key: name of loaded pcap file to generate from"""
        if packet_list_key not in self.packet_lists.keys():
            print(f"Key error {packet_list_key}")
            return
        send(self.packet_lists[packet_list_key])
        return len(self.packet_lists[packet_list_key])

class ClusterTopo( Topo ):
    """Class to manage the custom topology for this project.
    builds off of a simple single topo
    This script will handle generating traffic by
    sending commands to each server to run custom scripts."""
    def build( self, k=2, **_opts ):
        "k: number of hosts"
        self.k = k
        switch = self.addSwitch( 's1' )
        for h in irange( 1, k ):
            host = self.addHost( 'h%s' % h, ip=f"10.0.0.{h}" )
            print(f"Setting bw={self.cfg['host_bandwidth'][f'{h}']}, delay={self.cfg['host_latency'][f'{h}']}")
            self.addLink(switch, host, bw=self.cfg["host_bandwidth"][f"{h}"], delay=self.cfg["host_latency"][f"{h}"])
        packet_generator = self.addHost('pgen', ip='10.0.0.13')
        cross_traffic_generator = self.addHost('ctgen', ip='10.0.0.14')
        self.addLink(packet_generator, switch)
        self.addLink(cross_traffic_generator, switch)

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
        for i in range(1, k + 1):
            self.hosts.append(self.net.get(f'h{i}'))
        # self.hosts.append(self.net.get('pgen'))
        # self.hosts.append(self.net.get('ctgen'))
        self.experiment_csv_current_line = 0
        print("Increasing MTU size")
        for i in range(i,  k + 3):
            p = subprocess.Popen(f"sudo ifconfig s1-eth{i} mtu 65535", shell=True, stdout=subprocess.PIPE)
            if p.communicate()[1] is not None:
                print(f"[WARNING]: Failed to change MTU size on s1-eth{i}. Packets must not exceed 1500 bytes")
                break
        p = self.net.get('pgen').popen(f"sudo ifconfig pgen-eth0 mtu 65535")
        p = self.net.get('ctgen').popen(f"sudo ifconfig ctgen-eth0 mtu 65535")
        for i, host in enumerate(self.hosts):
            host.cmd(f"sudo ifconfig h{i+1}-eth0 mtu 65535")
        else:
            print("MTU Changed Successfully")
        # print("Loading PCAP files for experiments")
        # pcap_files = {"second_stage": self.cfg["second_stage_experiment_file"]}
        # pcap_files.update(self.cfg["first_stage_experiment_files"])
        # self.packet_generator = PacketGenerator(pcap_files)
        # print(self.packet_generator.packet_lists)
        choice = None
        while True:
            print('Please select an option')
            print('\tq: Quit Topology')
            print('\t1: Open CLI')
            print('\t2: Generate traffic (deprecated)')
            print('\t3: Open xterms for h1, ctgen, pgen')
            print('\t4: Run experiment')
            try:
                choice = input()
            except EOFError:
                self.quit()
            if choice == 'q':
                self.quit()
            elif choice == '1':
                CLI(self.net)
            # elif choice == '2':
            #     self.generate_traffic()
            elif choice == '3':
                CLI(self.net, stdin=sys.stdin, script="./open_xterms.sh")
            elif choice == '4':
                self.run_experiment()
            else:
                print(choice, 'is not a valid option')

    def generate_traffic(self, pcap_file=None):
        """Generates traffic"""
        if not pcap_file:
            pcap_file = self.cfg["default_pcap_file"]
        p = self.net.get('pgen').popen([
                'python3', './packet_generator.py',  "-f", self.cfg["default_pcap_file"]])
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
        """Helper function to clear all logs by executing commands on c0.
        Preserves header line in experiment.csv file"""
        # self.net.get('c0').cmd(f"sed -i '2,$d' ./experiment.csv", shell=True)
        # self.net.get('c0').cmd(f"sed -i '1,$d' ./ryu.log", shell=True)
        for log in ["./ryu.log", "./experiment.csv"]:
            # self.net.get('c0').cmd(f"truncate -s 0 {log}")
            with open(log, 'w') as f:
                f.write('')

    def stage_one_exp(self):
        """Build a confusion matrix for a given PCAP validation file"""
        results = dict()
        self.clear_experiment_logs()
        start_time = time.time()
        if self.cfg["cross_traffic"]["enabled"]:
            print(f"Cross traffic enabled in mode {self.cfg['cross_traffic']['mode']}")
            p1 = multiprocessing.Process(target = self.generate_cross_traffic)
            if self.cfg["cross_traffic"]["mode"] == "before":
                p1.start()
                time.sleep(1)
            elif self.cfg["cross_traffic"]["mode"] == "after":
                p1.start(delay=1)
        print(f"Cross traffic enabled: {self.cfg['cross_traffic']['enabled']}")
        print(f"Experiment started at {start_time}")
        # Value to track where to start in the CSV
        end_of_exp = {'cpu': 2089, 'network': 4325, 'memory': 5971}
        tmp_line_num = 1
        p = self.net.get('pgen').cmd(
            ['python3', './packet_generator.py', 
             "-f", self.cfg["first_stage_experiment_files"]["cpu"],
             "-f", self.cfg["first_stage_experiment_files"]["network"],
             "-f", self.cfg["first_stage_experiment_files"]["memory"],
             '-c', str(self.cfg["experiment_packet_count"])])
        # for exp, fname in self.cfg["first_stage_experiment_files"].items():
        #     # Clear the ryu log
        #     print(f"Running {exp} experiment from {fname}")
        #     results[exp] = dict()
        #     if not os.path.exists(fname):
        #         print("ERROR: Could not find file", fname)
        #         continue
            # end_of_exp[exp] = int(p.split('\n')[-2]) + tmp_line_num
            # tmp_line_num += int(p.split('\n')[-2])
            # for prediction_result in ["cpu", "network", "memory"]:
            #     p = subprocess.Popen(
            #         f'grep "PREDICTION: {prediction_result}" ./ryu.log | wc -l',
            #         shell=True, stdout=subprocess.PIPE)
            #     results[exp][prediction_result] = int(p.communicate()[0])
        if not os.path.exists(self.cfg["experiment_results"]):
            print("[ERROR] Could not find experiment results")
            return
        with open(self.cfg["experiment_results"], 'r') as f:
            controller_results = f.readlines()
            max_wait = 200
            i = 0
            while len(controller_results) < end_of_exp['memory']:
                i += 1
                if i == max_wait:
                    print("Timed out")
                    return
                print(f"Experiment file not finished (on line {len(controller_results)}), buffering for 1s")
                time.sleep(1)
                controller_results.extend(f.readlines())
            if self.cfg["cross_traffic"]["enabled"]:
                p1.terminate()
                self.net.get('ctgen').cmd('pkill iperf3',shell=True)
        #     print(len(controller_results))
        #     # print(f"Time for experiment: {time.time()-start_time}s")
        #     # print(f"Average packet handling time: {1000*(time.time()-start_time)/len(controller_results)}ms")
        #     print(end_of_exp)
        #     for prediction_result in ["cpu", "network", "memory"]:
        #         results['cpu'][prediction_result] = len([row for row in controller_results[1:end_of_exp['cpu']] if row.split(",")[0] == prediction_result])
        #         results['network'][prediction_result] = len([row for row in controller_results[end_of_exp['cpu']:end_of_exp['network']] if row.split(",")[0] == prediction_result])
        #         results['memory'][prediction_result] = len([row for row in controller_results[end_of_exp['network']:end_of_exp['memory']] if row.split(",")[0] == prediction_result])
        # print(pd.DataFrame.from_dict(results).to_markdown())
        # total_count = 0
        # total_correct = 0
        # for exp in ["cpu", "memory", "network"]:
        #     for label in ["cpu", "memory", "network"]:
        #         total_count += results[exp][label]
        #         if exp == label:
        #             total_correct += results[exp][label]
        # print("Correct:", total_correct)
        # print("Total count:", total_count)
        # print(f"Total Accuracy: {100*total_correct/total_count}%")
        if self.cfg["cross_traffic"]["enabled"]:
            p1.terminate()
            self.net.get('ctgen').cmd('pkill -9 iperf3',shell=True)
        return

    def stage_two_exp(self):
        """Report average latency, bandwidth, utilization, etc.
        for each server"""
        # Clear the ryu log
        # with open(RYU_LOGFILE, 'w') as f:
        #     f.write('')
        # self.clear_experiment_logs()
        print(f"Running 2nd stage test")
        if self.cfg["cross_traffic"]["enabled"]:
            print(f"Cross traffic enabled in mode {self.cfg['cross_traffic']['mode']}")
            p1 = multiprocessing.Process(target = self.generate_cross_traffic)
            if self.cfg["cross_traffic"]["mode"] == "before":
                p1.start()
                time.sleep(1)
            elif self.cfg["cross_traffic"]["mode"] == "after":
                p1.start(delay=1)
            p = self.net.get('pgen').popen(['python3', './packet_generator.py', "-f", self.cfg["second_stage_experiment_file"], '-c', str(self.cfg["experiment_packet_count"])])
            p.communicate()
            p1.terminate()
            self.net.get('ctgen').cmd('pkill iperf3',shell=True)
        else:
            p = self.net.get('pgen').popen(['python3', './packet_generator.py', "-f", self.cfg["second_stage_experiment_file"], '-c', str(self.cfg["experiment_packet_count"])])
            p.communicate()
        if not os.path.exists(self.cfg["experiment_results"]):
            print("[ERROR] Could not find experiment results")
            return
        results = csv.DictReader(open(self.cfg["experiment_results"], 'r'))
        latencies = [int(result["latency"].replace("ms", "")) for result in results]
        bandwidths = [int(result["bandwidth"]) for result in results]
        print(latencies)
        print(bandwidths)
        if len(latencies) > 0:
            print("Average latency:", sum(latencies)/len(latencies))
        else:
            print("Could not retrieve latencies")
        if len(bandwidths) > 0:
            print("Average bandwidth:", sum(bandwidths)/len(bandwidths))
        else:
            print("Could not retrieve bandwidths")

    def quit(self):
        """Necessary to let Mininet clean itself for next run"""
        print('Shutting Down Topology')
        self.net.stop()
        exit()


    def generate_cross_traffic(self, delay=0):
        print("Setting up iperf servers on machines")
        for i, host in enumerate(self.hosts):
            p = host.popen(f"iperf3 -s -D")
            print(p.communicate())
        ip_list = [f'10.0.0.{i}' for i in range(1, self.k + 1)]
        time.sleep(delay)
        for ip in ip_list:
            # os.remove(f'./cross_traffic_log_{ip}.log')
            with open(f'./cross_traffic_log_{ip}.log', 'w') as f:
                f.write('')
        for ip in ip_list:
            iperf_cmd = f'''\
iperf3 -i {self.cfg["cross_traffic"]["logging_interval"]} \
-c {ip} -u -t {self.cfg["cross_traffic"]["max_transmit_time"]} \
--logfile ./cross_traffic_log_{ip}.log \
--zerocopy -l {self.cfg["cross_traffic"]["buffer_length"]} -w 2048'''
            print(iperf_cmd)
            p = self.net.get('ctgen').popen(iperf_cmd, shell=True)
        return


if __name__ == "__main__":
    topo = ClusterTopo()

