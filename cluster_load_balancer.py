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
FIXED_EPOCH_TIME = 1668036116


class UtilizationQueue(Queue):
    """Wrapper for queue which allows for multiple puts at once, handles
    flushing the queue when it gets too full"""
    def __init__(self, maxsize=0):
        super().__init__(maxsize=maxsize)

    def util_put(self, item, n=1):
        """put method that allows for multiple insertions and manages pops"""
        if(self.qsize() + n >= self.maxsize):
            for i in range(int(n)):
                self.get()
        for i in range(int(n)):
            self.put(item)


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

    USE_ML_MODEL = True
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
        # Instantiate utilization queue for each cluster
        self.util_queues = {cluster_name: UtilizationQueue(1000)
                            for cluster_name in self.ML_SERVER_MAPPING.keys()}
        # Use this to track power consumption btw first and second stage
        self.current_packet_power = 0
        # Track the dst workload cluster btw first and second stage
        self.dst_cluster = ''
        # Clear the log file
        if os.path.exists('./ryu.log'):
            with open('./ryu.log', 'w') as f:
                f.write('')
        fieldnames = ["workload_type", "selected_server"]
        for cluster in self.ML_SERVER_MAPPING.values():
            fieldnames.extend([server[0] for server in cluster])
        self.data_writer = csv.DictWriter(open('./experiment.csv', 'w'), fieldnames)
        if self.USE_ML_MODEL:
            if not os.path.exists(self.PATH_TO_ML_MODEL):
                raise FileNotFoundError("Cannot find ML model!")
            self.ml_model = torch.load(self.PATH_TO_ML_MODEL)
            self.ml_model.eval()
        with open('./ip_option_decode.json', 'r') as f:
            self.ip_option_decode = json.load(f)

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
        # self.logger.info(f"ML Input is: {ml_input.tolist()}")
        # # TESTING
        # # See if this matches the current input
        # csv_check = next(self.CSV_CHECK)
        # csv_check = np.array([
        #     csv_check[3] / 13,
        #     ip_header.total_length / 1500,
        #     csv_check[0] == 0,
        #     csv_check[0] == 1,
        #     csv_check[0] == 2,
        #     csv_check[0] == 3,
        #     csv_check[0] == 4,
        #     csv_check[0] == 5,
        #     csv_check[0] == 6,
        #     csv_check[0] == 7,
        #     csv_check[1] == 0,
        #     csv_check[1] == 1,
        #     csv_check[1] == 2,
        #     csv_check[1] == 3,
        #     csv_check[2] == 0,
        #     csv_check[2] == 1,
        #     csv_check[2] == 2,
        #     csv_check[2] == 3,
        #     csv_check[2] == 4,
        #     csv_check[2] == 5,
        #     csv_check[2] == 6,
        #     csv_check[2] == 7,
        #     csv_check[4] == 0,
        #     csv_check[4] == 1,
        #     csv_check[4] == 2,
        #     csv_check[4] == 3,
        #     csv_check[5] == 0,
        #     csv_check[5] == 1,
        #     csv_check[5] == 2,
        #     csv_check[5] == 3,
        #     csv_check[5] == 4,
        #     csv_check[5] == 5,
        #     csv_check[5] == 6,
        #     csv_check[5] == 7,
        #     # datetime.datetime.fromtimestamp(options_organized['timestamp']).hour // 4
        # ])
        # self.logger.info(csv_check)
        self.logger.info(f"{self.packet_counter}")
        self.packet_counter += 1
        # Track the power consumption of the given packet
        self.current_packet_power = options_organized['power']
        if self.USE_ML_MODEL:
            return self.predict_using_lr(ml_input)
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

    def determine_output_host(self, ip_header, cluster_name):
        """Determine the best output server from a cluster
        based on machine learning algorithm"""
        # Do machine learning here
        # Calculate current utilization percentages in this cluster
        data = {}
        self.logger.info("Server utilization balance:")
        data.update(self.get_utils())
        # For now, do a random server
        server = random.choice(self.ML_SERVER_MAPPING[cluster_name])
        self.logger.info(f"Selecting random server in cluster: {server}")
        self.util_queues[cluster_name].util_put(server[1], self.current_packet_power)
        data.update({
            "workload_type": cluster_name,
            "selected_server": server[0],
        })
        print(data)
        self.data_writer.writerow(data)
        return server

    def get_utils(self):
        """Helper function to return a dict of all the current server utils"""
        util_balance = {}
        for cluster_name in self.ML_SERVER_MAPPING.keys():
            for server in self.ML_SERVER_MAPPING[cluster_name]:
                qsize = self.util_queues[cluster_name].qsize()
                # Avoid div0 exception
                if qsize == 0:
                    util_balance[server[0]] = 0
                    continue
                util_balance[server[0]] = self.util_queues[cluster_name].queue.count(server) / qsize
        return util_balance

    def fake_ml(self, ml_input):
        return ml_input[1]

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