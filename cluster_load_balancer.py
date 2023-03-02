# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import time
from ryu.base import app_manager
from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.mac import haddr_to_int
from ryu.lib.packet.ether_types import ETH_TYPE_IP
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
import numpy as np
from numpy import genfromtxt
import torch
import torch.nn as nn
import torch.nn.functional as F
from numpy import genfromtxt
import pandas as pd
import datetime
import os
import json
import sys
from queue import Queue
import csv
import itertools
import joblib
FIXED_EPOCH_TIME = 1668036116


class UtilizationQueue(Queue):
    """Wrapper for queue which allows for multiple puts at once, handles
    flushing the queue when it gets too full"""
    def __init__(self, maxsize=0):
        super().__init__(maxsize=maxsize)
        # Track the ratio of sum to qsize (percentage full)
        self.current_utilization = 0
        # Track the sum each time an item is pushed onto queue
        self.sum = 0

    def util_put(self, item, n=1):
        """put method that allows for multiple insertions and manages pops"""
        if(self.qsize() + n >= self.maxsize):
            for i in range(int(n)):
                self.sum -= self.get()
        for i in range(int(n)):
            self.sum += item
            self.put(item)

    def get_utilization(self):
        if self.qsize() == 0:
            return 0
        return self.sum / self.qsize()
    



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    VIRTUAL_IP = '10.0.0.100'  # The virtual server IP

    SERVER1_IP = '10.0.0.1'
    SERVER1_MAC = '00:00:00:00:00:01'
    SERVER1_PORT = 1
    SERVER2_IP = '10.0.0.2'
    SERVER2_MAC = '00:00:00:00:00:02'
    SERVER2_PORT = 2
    SERVER3_IP = '10.0.0.3'
    SERVER3_MAC = '00:00:00:00:00:03'
    SERVER3_PORT = 3

    PATH_TO_ML_MODEL = '/home/mininet/machine_learning/model.pt'
    # TESTING
    # CSV_CHECK = iter(genfromtxt("/home/mininet/network_topo/labeled_datasets/validation/all.csv", delimiter=','))
    # Skip header
    # next(CSV_CHECK)
    
    # maps the workload clusters to a list of all their servers
    ML_SERVER_MAPPING = {
        'cpu': [(f'10.0.0.{i}', i) for i in range(1, 5)],
        'network': [(f'10.0.0.{i}', i) for i in range(5, 9)],
        'memory': [(f'10.0.0.{i}', i) for i in range(9, 13)]
    }
    ROUND_ROBIN_ML_SERVER_MAPPING = {
        key: itertools.cycle(val) for key, val in ML_SERVER_MAPPING.items()
    }
    # maps index of ML algorithm output to the corresponding workload type
    ML_WORKLOAD_MAPPING = {
        0: "cpu",
        1: "network",
        2: "memory"
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ml_model = None
        self.packet_counter = 1
        # Use this to track power consumption btw first and second stage
        self.current_packet_power = 0
        # Track the dst workload cluster btw first and second stage
        self.dst_cluster = ''
        # Clear the log file
        with open('./ryu.log', 'w') as f:
            f.write('')
        with open('./experiment.csv', 'w') as f:
            f.write('')
        with open('./topo_cluster_cfg.json', 'r') as f:
            self.topo_cluster_cfg = json.load(f)
        with open('./ip_option_decode.json', 'r') as f:
            self.ip_option_decode = json.load(f)
        # Instantiate utilization queue for each cluster
        # Each host gets its own util queue to track its local utilization
        self.util_queues = {cluster_name: [UtilizationQueue(self.topo_cluster_cfg["util_queue_length"]) for i in range(4)]
                            for cluster_name in self.ML_SERVER_MAPPING.keys()}
        fieldnames = ["workload_type", "selected_server", "latency", "bandwidth", "time_handled"]
        for cluster in self.ML_SERVER_MAPPING.keys():
            fieldnames.extend([f"{cluster}_{i}" for i in range(4)])
        self.experiment_file = open('./experiment.csv', 'w')
        self.data_writer = csv.DictWriter(self.experiment_file, fieldnames)
        self.data_writer.writeheader()
        if self.topo_cluster_cfg["ml_type"] == 'lr':
            if not os.path.exists(self.topo_cluster_cfg['lr_model_path']):
                raise FileNotFoundError("Cannot find ML model!")
            self.ml_model = torch.load(self.topo_cluster_cfg['lr_model_path'])
            self.ml_model.eval()
        elif self.topo_cluster_cfg["ml_type"] == 'rf':
            if not os.path.exists(self.topo_cluster_cfg['rf_model_path']):
                raise FileNotFoundError("Cannot find ML model!")
            self.ml_model = joblib.load(self.topo_cluster_cfg['rf_model_path'])
        else:
            self.logger.warning("No ML model selected! Using random predictions")
            self.ml_model = None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # Ryu decorator for packet_in messages
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst_mac = eth.dst
        src_mac = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 10, match, actions)

        # Handle ARP Packet
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_header = pkt.get_protocol(arp.arp)
            if arp_header.dst_ip == self.VIRTUAL_IP and arp_header.opcode == arp.ARP_REQUEST:
                self.logger.info("***************************")
                self.logger.info("---Handle ARP Packet---")
                # Build an ARP reply packet using source IP and source MAC
                reply_packet = self.generate_arp_reply(arp_header.src_ip, arp_header.src_mac)
                actions = [parser.OFPActionOutput(in_port)]
                packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY,
                                                 data=reply_packet.data, actions=actions, buffer_id=0xffffffff)
                datapath.send_msg(packet_out)
                self.logger.info("Sent the ARP reply packet")
                return
        if eth.ethertype != ETH_TYPE_IP:
            self.logger.info("THIS IS NOT A TCP PACKET!")

        if eth.ethertype == ETH_TYPE_IP:
            self.logger.info("***************************")
            self.logger.info("---Handle TCP Packet---")
            # Built-in Ryu function to extract packet header
            ip_header = pkt.get_protocol(ipv4.ipv4)

            # Send to prediction function
            packet_handled = self.handle_tcp_packet(
                datapath, in_port, ip_header,
                parser, dst_mac, src_mac, msg, ofproto)
            self.logger.info("TCP packet handled: " + str(packet_handled))
            if packet_handled:
                return

        # Send if other packet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # Source IP and MAC passed here now become the destination for the reply packet
    def generate_arp_reply(self, dst_ip, dst_mac):
        self.logger.info("Generating ARP Reply Packet")
        self.logger.info("ARP request client ip: " + dst_ip + ", client mac: " + dst_mac)
        arp_target_ip = dst_ip  # the sender ip
        arp_target_mac = dst_mac  # the sender mac
        # Making the load balancer IP as source IP
        src_ip = self.VIRTUAL_IP
        src_mac = self.select_src_mac(arp_target_ip)
        self.logger.info("Selected server MAC: " + src_mac)

        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
        )
        pkt.add_protocol(
            arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip,
                    dst_mac=arp_target_mac, dst_ip=arp_target_ip)
        )
        pkt.serialize()
        self.logger.info("Done with processing the ARP reply packet")
        return pkt

    def select_src_mac(self, arp_target_ip):
        # if arp_target_ip == '10.0.0.3':
        #     print("[DEBUG]: From 10.0.0.3!!")
        #     src_mac = self.SERVER1_MAC
        # else:
        #     src_mac = self.SERVER2_MAC
        return self.SERVER1_MAC

    def split_options(self, options):
        """Function which splits the options array into multiple
        lists based on the given option size"""
        split_list = []
        i = 0
        while i < len(options):
            if options[i] == 0:
                break
            # print(f"Option type {options[i]}")
            opt_size = options[i + 1]
            # print(f"Option size {opt_size}")
            if opt_size < 3:
                raise Exception("Invalid Options Size!")
            split_list.append(options[i:i+opt_size])
            # print("Appending list", options[i:i+opt_size])
            i = i+opt_size
        return split_list

    def determine_output_cluster(self, ip_header):
        """Use ML on the IP header to determine the correct output cluster.
        Returns first host by default if there is not a good input in the ip_header"""
        if not ip_header.option:
            self.logger.warning("Options Not Found")
            return self.SERVER1_IP, self.SERVER1_PORT
        try:
            options = self.split_options(list(ip_header.option))
        except Exception as err:
            print(f"[WARNING]: {err}")
            return self.SERVER1_IP, self.SERVER1_PORT
        self.logger.info(options)
        options_organized = {}
        for opt in options:
            if str(opt[0]) not in self.ip_option_decode:
                print("[WARNING]: Info Type Not Recognized!")
                return self.SERVER1_IP, self.SERVER1_PORT
            self.logger.info(f"Option {opt} loaded: {self.ip_option_decode[str(opt[0])]['name']}, value: {str(opt[2])}")
            options_organized[self.ip_option_decode[str(opt[0])]['name']] = float(opt[2])
        # If we made it this far, we can actually use the options
        # First need to process them into a numpy array
        # Use one hot encoding
        ml_input = np.array([
            options_organized['timestamp'] // 16 / 13,
            ip_header.total_length / 1500,
            options_organized['category'] == 0,
            options_organized['category'] == 1,
            options_organized['category'] == 2,
            options_organized['category'] == 3,
            options_organized['category'] == 4,
            options_organized['category'] == 5,
            options_organized['category'] == 6,
            options_organized['category'] == 7,
            options_organized['permissions priority'] // 16 == 0,
            options_organized['permissions priority'] // 16 == 1,
            options_organized['permissions priority'] // 16 == 2,
            options_organized['permissions priority'] // 16 == 3,
            options_organized['permissions priority'] % 16 == 0,
            options_organized['permissions priority'] % 16 == 1,
            options_organized['permissions priority'] % 16 == 2,
            options_organized['permissions priority'] % 16 == 3,
            options_organized['permissions priority'] % 16 == 4,
            options_organized['permissions priority'] % 16 == 5,
            options_organized['permissions priority'] % 16 == 6,
            options_organized['permissions priority'] % 16 == 7,
            options_organized['timestamp'] % 16 == 0,
            options_organized['timestamp'] % 16 == 1,
            options_organized['timestamp'] % 16 == 2,
            options_organized['timestamp'] % 16 == 3,
            options_organized['power'] == 0,
            options_organized['power'] == 1,
            options_organized['power'] == 3,
            options_organized['power'] == 2,
            options_organized['power'] == 4,
            options_organized['power'] == 5,
            options_organized['power'] == 6,
            options_organized['power'] == 7,
            # datetime.datetime.fromtimestamp(options_organized['timestamp']).hour // 4
        ])
        self.logger.info(f"{self.packet_counter}")
        self.packet_counter += 1
        # Track the power consumption of the given packet
        self.current_packet_power = options_organized['power']
        if self.ml_model is None:
            return self.fake_ml()
        if self.topo_cluster_cfg['ml_type'] == 'lr':
            return self.predict_using_lr(ml_input)
        elif self.topo_cluster_cfg['ml_type'] == 'rf':
            return self.predict_using_rf(ml_input)
        if self.fake_ml(ml_input) == 2:
            return self.SERVER2_IP, self.SERVER2_PORT
        return self.SERVER1_IP, self.SERVER1_PORT

    def predict_using_lr(self, ml_input):
        """Uses ML Model to predict target server.
        ML output will be 3-element array with the
        highest value corresponding to the predicted
        server. Each index is mapped to the correct IP
        address of the server."""
        pred = self.ml_model(
            torch.from_numpy(ml_input).float()).data.numpy()
        self.logger.info(f"Prediction tensor: {pred}")
        # pred.argmax: Numpy function to return index of max elem
        self.logger.info(
            f"""PREDICTION: \
{self.ML_WORKLOAD_MAPPING[pred.argmax()]}""")
        return self.ML_WORKLOAD_MAPPING[pred.argmax()]

    def predict_using_rf(self, ml_input):
        pred = self.ml_model.predict(
            ml_input.reshape(1,-1)).flatten()
        self.logger.info(f"Prediction tensor: {pred}")
        # pred.argmax: Numpy function to return index of max elem
        self.logger.info(
            f"""PREDICTION: \
{self.ML_WORKLOAD_MAPPING[pred.argmax()]}""")
        return self.ML_WORKLOAD_MAPPING[pred.argmax()]

    def determine_output_host(self, ip_header, cluster_name):
        """Determine the best output server from a cluster
        based on machine learning algorithm"""
        # Do machine learning here
        # Calculate current utilization percentages in this cluster
        data = {}
        data.update(self.get_utils())
        # For now, do a round robin selection
        server = next(self.ROUND_ROBIN_ML_SERVER_MAPPING[cluster_name])
        # Pushes a '1' onto the util queue for the given server
        # Index in list calculated using mod function (four servers per cluster)
        self.update_all_util_queues(cluster_name, (int(server[1]) + 1) % 4, self.current_packet_power)
        self.logger.info(f"Selecting random server in cluster: {server}")
        data.update({
            "workload_type": cluster_name,
            "selected_server": server[0],
            "latency": self.topo_cluster_cfg["host_latency"][str(server[1])],
            "bandwidth": self.topo_cluster_cfg["host_bandwidth"][str(server[1])],
            "time_handled": time.time()
        })
        self.data_writer.writerow(data)
        self.experiment_file.flush()
        return server

    # def get_utils(self):
    #     """Helper function to return a dict of all the current server utils"""
    #     util_balance = {}
    #     for cluster_name in self.ML_SERVER_MAPPING.keys():
    #         for server in self.ML_SERVER_MAPPING[cluster_name]:
    #             qsize = self.util_queues[cluster_name].qsize()
    #             # Avoid div0 exception
    #             if qsize == 0:
    #                 util_balance[server[0]] = 0
    #                 continue
    #             util_balance[server[0]] = self.util_queues[cluster_name].queue.count(server[0]) / qsize
    #     return util_balance

    def get_utils(self):
        """Returns the calculated utilization for every queue"""
        all_utilizations = {}
        for cluster_name in self.ML_SERVER_MAPPING.keys():
            for i, util_queue in enumerate(self.util_queues[cluster_name]):
                all_utilizations[f"{cluster_name}_{i}"] = util_queue.get_utilization()
        return all_utilizations

    def update_all_util_queues(self, cluster_name, server, n):
        for cluster in self.ML_SERVER_MAPPING.keys():
            for i in range(4):
                if cluster == cluster_name and i == server:
                    self.util_queues[cluster_name][server].util_put(1, n)
                else:
                    # Push back one item to represent one unit of time
                    self.util_queues[cluster_name][server].util_put(0, 1)
        


    def fake_ml(self):
        return random.choice(list(self.ML_WORKLOAD_MAPPING.values()))

    def handle_tcp_packet(
            self, datapath, in_port, ip_header, parser,
            dst_mac, src_mac, msg, ofproto):
        """Two stage prediction function
        Gets ML predicted cluster (cpu, network, memory)
        and then determines the best host in this cluster"""
        packet_handled = False
        server_dst_ip, server_out_port = self.determine_output_host(
            ip_header, self.determine_output_cluster(ip_header))
        self.logger.info(f"Sending to server {server_dst_ip} on port {server_out_port}")
        actions = [parser.OFPActionSetField(ipv4_dst=server_dst_ip),
                    parser.OFPActionOutput(server_out_port)]
        # Send Packet Out Message
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
                # Route to server
        # match = parser.OFPMatch(
        #     in_port=in_port,
        #     eth_type=ETH_TYPE_IP,
        #     ip_proto=ip_header.proto,
        #     ipv4_dst=self.VIRTUAL_IP)
        # self.add_flow(datapath, 20, match, actions)
        # self.logger.info("<==== Added TCP Flow- Route to Server: " + str(server_dst_ip) +
        #                     " from Client :" + str(ip_header.src) + " on Switch Port:" +
        #                     str(server_out_port) + "====>")

        # Reverse route from server
        # match = parser.OFPMatch(in_port=server_out_port, eth_type=ETH_TYPE_IP,
        #                         ip_proto=ip_header.proto,
        #                         ipv4_src=server_dst_ip,
        #                         eth_dst=src_mac)
        # actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
        #             parser.OFPActionOutput(in_port)]

        # self.add_flow(datapath, 20, match, actions)
        # self.logger.info("<==== Added TCP Flow- Reverse route from Server: " + str(server_dst_ip) +
        #                     " to Client: " + str(src_mac) + " on Switch Port:" +
        #                     str(in_port) + "====>")
        packet_handled = True
        return packet_handled

def quit():
    sys.exit()