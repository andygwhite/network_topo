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

import copy
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
from LBMinResourceModel import LBMinResourceModel
# from UtilizationQueue import UtilizationQueue
from UtilizationStack import UtilizationStack

FIXED_EPOCH_TIME = 1668036116

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    SERVER1_MAC = '00:00:00:00:00:01'

    VIRTUAL_IP = '10.0.0.100'  # The virtual server IP

    # PATH_TO_ML_MODEL = '/home/mininet/machine_learning/model.pt'
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

    ROUND_ROBIN_ML_CLUSTER_MAPPING = itertools.cycle(list(ML_WORKLOAD_MAPPING.values()))

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.logger.setLevel(5)
        self.mac_to_port = {}
        # self.logger.disabled = True
        self.ml_model = None
        self.packet_counter = 1
        # self.logger.setLevel('CRITICAL')
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
        self.util_stacks = {cluster_name: [UtilizationStack(capacity=self.topo_cluster_cfg["util_stack_capacity"]) for i in range(4)]
                            for cluster_name in self.ML_SERVER_MAPPING.keys()}
        self.bandwidths = [self.topo_cluster_cfg["host_bandwidth"][str(i+1)] for i in range(12)]
        self.round_trip_times = [int(self.topo_cluster_cfg["host_latency"][str(i+1)].replace("ms","")) for i in range(12)]
        self.packetlosses = [1e-6 for i in range(12)]
        fieldnames = ["workload_type", "selected_server", "latency", "bandwidth", "packet_loss", "time_handled", "utilization"]
        fieldnames.extend([f"bandwidth_{i}" for i in range(4)])
        fieldnames.extend([f"packetloss_{i}" for i in range(4)])
        fieldnames.extend([f"rtt_{i}" for i in range(4)])
        fieldnames.extend([f"utilization_{i}" for i in range(4)])
        for cluster in self.ML_SERVER_MAPPING.keys():
            fieldnames.extend([f"{cluster}_{i}" for i in range(4)])
        self.experiment_file = open('./experiment.csv', 'w')
        self.data_writer = csv.DictWriter(self.experiment_file, fieldnames)
        # self.data_writer.writeheader()
        if self.topo_cluster_cfg["first_stage_ml_type"] == 'lr':
            if not os.path.exists(self.topo_cluster_cfg['first_stage_lr_model_path']):
                raise FileNotFoundError("Cannot find ML model!")
            self.first_stage_ml_model = torch.load(self.topo_cluster_cfg['first_stage_lr_model_path'])
            self.first_stage_ml_model.eval()
        elif self.topo_cluster_cfg["first_stage_ml_type"] == "none":
            self.logger.warning("No first stage ML model selected! Using round robin")
            self.first_stage_ml_model = None
        else:
            model_path = self.topo_cluster_cfg[f'first_stage_{self.topo_cluster_cfg["first_stage_ml_type"]}_model_path']
            self.logger.info(f"Loading {model_path}")
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Cannot find ML model at {model_path}!")
            self.first_stage_ml_model = joblib.load(model_path)

        # Repeat for loading second stage model
        if self.topo_cluster_cfg["second_stage_ml_type"] == 'lr':
            if not os.path.exists(self.topo_cluster_cfg['second_stage_lr_model_path']):
                raise FileNotFoundError("Cannot find ML model!")
            self.second_stage_ml_model = torch.load(self.topo_cluster_cfg['second_stage_lr_model_path'])
            self.second_stage_ml_model.eval()
        elif self.topo_cluster_cfg["second_stage_ml_type"] == "none":
            self.logger.warning("No second stage ML model selected! Using round robin")
            self.second_stage_ml_model = None
        elif self.topo_cluster_cfg["second_stage_ml_type"] == "min":
            self.logger.warning("Using minimum utilization")
            self.second_stage_ml_model = LBMinResourceModel()
        else:
            model_path = self.topo_cluster_cfg[f'second_stage_{self.topo_cluster_cfg["second_stage_ml_type"]}_model_path']
            self.logger.info(f"Loading {model_path}")
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Cannot find ML model at {model_path}!")
            self.second_stage_ml_model = joblib.load(model_path)
        # if self.topo_cluster_cfg["second_stage_ml_type"] == 'svm':
        #     if not os.path.exists(self.topo_cluster_cfg['second_stage_svm_model_path']):
        #         raise FileNotFoundError("Cannot find ML model!")
        #     self.second_stage_ml_model = joblib.load(self.topo_cluster_cfg['second_stage_svm_model_path'])
        # elif self.topo_cluster_cfg["second_stage_ml_type"] == 'rf':
        #     if not os.path.exists(self.topo_cluster_cfg['second_stage_rf_model_path']):
        #         raise FileNotFoundError("Cannot find ML model!")
        #     self.second_stage_ml_model = joblib.load(self.topo_cluster_cfg['second_stage_rf_model_path'])
        # else:
            
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
            if arp_header.dst_ip in [self.VIRTUAL_IP, '10.0.0.111'] and arp_header.opcode == arp.ARP_REQUEST:
                self.logger.info("***************************")
                self.logger.info("---Handle ARP Packet---")
                # Build an ARP reply packet using source IP and source MAC
                reply_packet = self.generate_arp_reply(arp_header.src_ip, arp_header.src_mac, original_dst=arp_header.dst_ip)
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
            if ip_header.dst == self.VIRTUAL_IP:
                # Send to prediction function
                packet_handled = self.handle_tcp_packet(
                    datapath, in_port, ip_header,
                    parser, dst_mac, src_mac, msg, ofproto)
                self.logger.info("TCP packet handled: " + str(packet_handled))
                return
                # if packet_handled:
                #     return
            elif ip_header.dst == '10.0.0.111':
                packet_handled = self.handle_control_packet(pkt.protocols[-1].data.data)

        # Send if other packet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        self.logger.info("Default action taken")
        datapath.send_msg(out)

    # Source IP and MAC passed here now become the destination for the reply packet
    def generate_arp_reply(self, dst_ip, dst_mac, original_dst):
        self.logger.info("Generating ARP Reply Packet")
        self.logger.info("ARP request client ip: " + dst_ip + ", client mac: " + dst_mac)
        arp_target_ip = dst_ip  # the sender ip
        arp_target_mac = dst_mac  # the sender mac
        # Making the load balancer IP as source IP
        src_ip = original_dst
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
            opt_size = options[i + 1]
            if opt_size < 3:
                raise Exception("Invalid Options Size!")
            split_list.append(options[i:i+opt_size])
            i = i+opt_size
        return split_list

    def determine_output_cluster(self, ip_header):
        """Use ML on the IP header to determine the correct output cluster.
        Returns first host by default if there is not a good input in the ip_header"""
        if not ip_header.option:
            raise Exception("Options Not Found")
        options = self.split_options(list(ip_header.option))
        self.logger.info(options)
        options_organized = {}
        for opt in options:
            if str(opt[0]) not in self.ip_option_decode:
                raise Exception("Info Type Not Recognized")
            self.logger.info(f"Option {opt} loaded: {self.ip_option_decode[str(opt[0])]['name']}, value: {str(opt[2])}")
            options_organized[self.ip_option_decode[str(opt[0])]['name']] = float(opt[2])
        # Check all of the options inputs
        if options_organized['category'] > 7:
            raise Exception(f"Invalid Category Value of {options_organized['category']}")
        if options_organized['permissions priority'] // 16 > 3:
            raise Exception(f"Invalid Permissions Value of {options_organized['permissions priority'] // 16}")
        if options_organized['permissions priority'] % 16 > 7:
            raise Exception(f"Invalid Priority Value of {options_organized['permissions priority'] % 16}")
        if options_organized['timestamp'] % 16 > 3:
            raise Exception(f"Invalid Time of Day Value of {options_organized['timestamp'] % 16}")
        if options_organized['power'] > 7:
            raise Exception(f"Invalid Power Value of {options_organized['power']}")
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
        if self.first_stage_ml_model is None:
            return self.fake_ml()
        if self.topo_cluster_cfg['first_stage_ml_type'] == 'lr':
            return self.first_stage_predict_using_lr(ml_input)
        else:
            return self.first_stage_predict_using_sklearn(ml_input)

    def first_stage_predict_using_lr(self, ml_input):
        """Uses ML Model to predict target server.
        ML output will be 3-element array with the
        highest value corresponding to the predicted
        server. Each index is mapped to the correct IP
        address of the server."""
        pred = self.first_stage_ml_model(
            torch.from_numpy(ml_input).float()).data.numpy()
        self.logger.info(f"Prediction tensor: {pred}")
        # pred.argmax: Numpy function to return index of max elem
        self.logger.info(
            f"""PREDICTION: \
{self.ML_WORKLOAD_MAPPING[pred.argmax()]}""")
        return self.ML_WORKLOAD_MAPPING[pred.argmax()]

    def second_stage_predict_using_lr(self, cluster, ml_input):
        """Uses ML Model to predict target server.
        ML output will be 3-element array with the
        highest value corresponding to the predicted
        server. Each index is mapped to the correct IP
        address of the server."""
        # Quick and dirty normalization
        avg_bw = sum(self.bandwidths)/len(self.bandwidths)
        if avg_bw == 0:
            avg_bw = 1
        avg_pl = sum(self.packetlosses)/len(self.packetlosses)
        if avg_pl == 0:
            avg_pl = 1
        avg_rtt = sum(self.round_trip_times)/len(self.round_trip_times)
        if avg_rtt == 0:
            avg_rtt = 1
        divisor_array = np.array([
            avg_bw,avg_bw,avg_bw,avg_bw,
            avg_rtt,avg_rtt,avg_rtt,avg_rtt,
            avg_pl,avg_pl,avg_pl,avg_pl,
            1,1,1,1
        ])
        ml_input = ml_input / divisor_array
        self.logger.info(ml_input)
        pred = self.second_stage_ml_model(
            torch.from_numpy(ml_input).float()).data.numpy()
        self.logger.info(f"Prediction tensor: {pred}")
        # pred.argmax: Numpy function to return index of max elem
        self.logger.info(
            f"""PREDICTION: \
{self.ML_SERVER_MAPPING[cluster][pred.argmax()]}""")
        return self.ML_SERVER_MAPPING[cluster][pred.argmax()]

    def first_stage_predict_using_sklearn(self, ml_input):
        pred = self.first_stage_ml_model.predict(
            ml_input.reshape(1,-1)).flatten()
        self.logger.info(f"Prediction input: {ml_input}")
        self.logger.info(
            f"FIRST STAGE PREDICTION: {pred}")
        return self.ML_WORKLOAD_MAPPING[int(pred)]

    def first_stage_predict_using_rf(self, ml_input):
        pred = self.first_stage_ml_model.predict(
            ml_input.reshape(1,-1)).flatten()
        self.logger.info(f"Prediction tensor: {pred}")
        # pred.argmax: Numpy function to return index of max elem
        self.logger.info(
            f"""PREDICTION: \
{self.ML_WORKLOAD_MAPPING[pred.argmax()]}""")
        return self.ML_WORKLOAD_MAPPING[pred.argmax()]

    def second_stage_predict_using_rf(self, cluster, ml_input):
        pred = self.second_stage_ml_model.predict(
            ml_input.reshape(1,-1)).flatten()
        self.logger.info(f"Prediction input: {ml_input}")
        # pred.argmax: Numpy function to return index of max elem
        self.logger.info(
            f"SECOND STAGE PREDICTION: {pred} -> {pred.argmax()}")
        return self.ML_SERVER_MAPPING[cluster][pred.argmax()]
    
    def second_stage_predict(self, cluster, ml_input):
        pred = self.second_stage_ml_model.predict(
            ml_input.reshape(1,-1)).flatten()
        self.logger.info(f"Prediction input: {ml_input}")
        # pred.argmax: Numpy function to return index of max elem
        self.logger.info(
            f"SECOND STAGE PREDICTION: {pred}")
        return self.ML_SERVER_MAPPING[cluster][int(pred)]

    def determine_output_host(self, ip_header, cluster_name):
        """Determine the best output server from a cluster
        based on machine learning algorithm"""
        # Do machine learning here
        # Calculate current utilization percentages in this cluster
        data = {}
        utils = self.get_utils()
        data.update(utils)
        # For now, do a round robin selection
        # self.second_stage_predict_using_rf(self.get_network_conditions(cluster_name, utils))
        # server = next(self.ROUND_ROBIN_ML_SERVER_MAPPING[cluster_name])
        ml_input = self.get_network_conditions(cluster_name, utils)
        if self.second_stage_ml_model is None:
            server = next(self.ROUND_ROBIN_ML_SERVER_MAPPING[cluster_name])
        # elif self.topo_cluster_cfg['second_stage_ml_type'] == 'rf':
        #     server = self.second_stage_predict(cluster_name, ml_input)
        elif self.topo_cluster_cfg['second_stage_ml_type'] == 'lr':
            server = self.second_stage_predict_using_lr(cluster_name, ml_input)
        else:
            server = self.second_stage_predict(cluster_name, ml_input)

        # Pushes a '1' onto the util queue for the given server
        # Index in list calculated using mod function (four servers per cluster)
        self.logger.info(f"Server # in cluster: {(int(server[1]) - 1) % 4}")
        selected_utilization = self.util_stacks[cluster_name][(int(server[1]) - 1) % 4].get_utilization()
        self.update_all_util_stacks(cluster_name, (int(server[1]) - 1) % 4, self.current_packet_power)
        self.logger.info(f"Selected server in cluster: {server}")
        data.update({
            "workload_type": cluster_name,
            "selected_server": server[0],
            "latency": self.round_trip_times[server[1]-1],
            "bandwidth": self.bandwidths[server[1]-1],
            "packet_loss": self.packetlosses[server[1]-1],
            "time_handled": time.time(),
            "utilization": selected_utilization
        })
        data.update({f"bandwidth_{i}": ml_input[i] for i in range(4)})
        data.update({f"packetloss_{i}": ml_input[4+i] for i in range(4)})
        data.update({f"rtt_{i}": ml_input[8+i] for i in range(4)})
        data.update({f"utilization_{i}": ml_input[12+i] for i in range(4)})
        self.data_writer.writerow(data)
        self.experiment_file.flush()
        return server

    def get_utils(self):
        """Returns the calculated utilization for every queue"""
        all_utilizations = {}
        for cluster_name in self.ML_SERVER_MAPPING.keys():
            for i, util_stack in enumerate(self.util_stacks[cluster_name]):
                all_utilizations[f"{cluster_name}_{i}"] = util_stack.get_utilization()
        return all_utilizations

    def update_all_util_stacks(self, cluster_name, server, n):
        for cluster, cluster_util_stack in self.util_stacks.items():
            for i in range(4):
                if cluster == cluster_name and i == server:
                    self.util_stacks[cluster][i].util_push(3*n)
                else:
                    # Pop one active unit
                    self.util_stacks[cluster][i].util_pop()

    def get_network_conditions(self, cluster_name, utils):
        """Returns a list of the throughput, packet loss, rtt,
        and utilization of a given cluster.
        Takes current utils to avoid calculating twice"""
        # Get the host indexes corresponding to a given host
        # Cast to str to index json config file
        hosts = [str(server[1]) for server in self.ML_SERVER_MAPPING[cluster_name]]
        conditions = self.bandwidths[int(hosts[0])-1:int(hosts[-1])]
        conditions.extend(self.round_trip_times[int(hosts[0])-1:int(hosts[-1])])
        conditions.extend(self.packetlosses[int(hosts[0])-1:int(hosts[-1])])
        # conditions.extend([1.00E-6 for host in hosts])
        # conditions.extend([float(self.topo_cluster_cfg["host_latency"][host].replace('ms', ''))*2 for host in hosts])
        conditions.extend([cur_util for host_name, cur_util in utils.items() if host_name.find(cluster_name) != -1])
        self.logger.info(conditions)
        # Only give the utilization data
        return np.array(conditions)

    def fake_ml(self):
        self.logger.info("Using round robin")
        # return random.choice(list(self.ML_WORKLOAD_MAPPING.values()))
        return next(self.ROUND_ROBIN_ML_CLUSTER_MAPPING)

    def handle_control_packet(self, payload):
        """Updates the bandwidth table with values from control packet"""
        # Adjust units
        self.bandwidths = [float(int.from_bytes(payload[i:i+4], 'big'))/1000000 for i in range(0, 48, 4)]
        if self.topo_cluster_cfg['live_bandwidth_polling']['use_ping']:
            self.round_trip_times = [float(int.from_bytes(payload[i:i+4], 'big'))/1000 for i in range(48, 48*2, 4)]
            self.packetlosses = [float(int.from_bytes(payload[i:i+4], 'big'))/1000000 for i in range(48*2, len(payload), 4)]
        self.logger.info(f"Updated bandwidths: {self.bandwidths}")
        self.logger.info(f"Updated round trip times: {self.round_trip_times}")
        self.logger.info(f"Updated packetlosses: {self.packetlosses}")

        return True

    def handle_tcp_packet(
            self, datapath, in_port, ip_header, parser,
            dst_mac, src_mac, msg, ofproto):
        """Two stage prediction function
        Gets ML predicted cluster (cpu, network, memory)
        and then determines the best host in this cluster"""
        packet_handled = False
        if ip_header.dst == '10.0.0.111':
            self.logger.info("Incoming control packet!")
            return self.handle_control_packet(msg, ip_header, parser)
        is_ct_packet = ip_header.dst != self.VIRTUAL_IP
        if is_ct_packet:
            self.logger.info(f"Cross traffic packet headed for {ip_header.dst}")
            server_dst_ip, server_out_port = (
                ip_header.dst, int(ip_header.dst.replace('10.0.0.', '')))
        else:
            if self.topo_cluster_cfg['single_link_mode']:
                server_dst_ip, server_out_port = ('10.0.0.1', 1)
            else:
                try:
                    server_dst_ip, server_out_port = self.determine_output_host(
                        ip_header, self.determine_output_cluster(ip_header))
                except Exception as err:
                    self.logger.error(f"Error encountered: {err}")
                    self.logger.info("Dropping packet")
                    return packet_handled
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
        if not is_ct_packet:
            packet_handled = True
            return packet_handled

        # Route to server
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ETH_TYPE_IP,
            ip_proto=ip_header.proto,
            ipv4_dst=ip_header.dst)
        self.add_flow(datapath, 20, match, actions)
        self.logger.info("<==== Added TCP Flow- Route to Server: " + str(server_dst_ip) +
                            " from Client :" + str(ip_header.src) + " on Switch Port:" +
                            str(server_out_port) + "====>")

        # Reverse route from server
        match = parser.OFPMatch(in_port=server_out_port, eth_type=ETH_TYPE_IP,
                                ip_proto=ip_header.proto,
                                ipv4_src=server_dst_ip,
                                eth_dst=src_mac)
        actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                    parser.OFPActionOutput(in_port)]

        self.add_flow(datapath, 20, match, actions)
        self.logger.info("<==== Added TCP Flow- Reverse route from Server: " + str(server_dst_ip) +
                            " to Client: " + str(src_mac) + " on Switch Port:" +
                            str(in_port) + "====>")
        packet_handled = True
        return packet_handled


def quit():
    sys.exit()