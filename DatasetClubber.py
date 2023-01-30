"""
Author: Andy White
The purpose of this program is to use Scapy's built
in PCAP parse and modify features to edit
the PCAP files in the given dataset to have the 
extra IP options for our research.
Inputs: 
    - CFG file with modifications to make
        NOTE: This config file will also contain a dict
        which will assign generated datapoints of a specific
        category to an application (i.e. the packets from 
        'Amazon Prime Video' will only be assigned generated
        sets with the category label "Video")
    - File with all generated and LABELED extra info dicts
        NOTE: Since Packet length is a parameter pulled from 
        the packet dataset, a certain amount of the generated
        dataset shall be dependent on the packet length, and will
        be labeled unknown. The config file will specify the
        threshold to determine labeling (i.e. for all packets labeled
        unknown, the label of CPU-intensive will be given
        to any packet with a length under [threshold], etc.)
    - PCAP Dataset, divided into folders with the application name
"""

import random
from scapy.all import PcapReader, PcapWriter, IP, IPOption, NoPayload
import click
import os
import json
import csv
import itertools
import copy

FIXED_EPOCH_TIME = 1667952000

def absoluteFilePaths(directory):
    for dirpath,_,filenames in os.walk(directory):
        for f in filenames:
            yield os.path.abspath(os.path.join(dirpath, f))

class Clubber:
    def __init__(self, cfg):
        self.cfg = cfg
        if not os.path.exists(self.cfg["generated_dataset"]):
            raise FileNotFoundError("Cannot find generated dataset!")
        if not os.path.exists(self.cfg["pcap_dataset_main_dir"]):
            raise FileNotFoundError("Cannot find pcap dir!")
        if not os.path.exists(self.cfg["dataset_output_dir"]):
            os.mkdir(self.cfg["dataset_output_dir"])
        self.load_generated_dataset()
        print("Generated dataset loaded")
        # Create Pcap writers
        pcap_validation_writers = dict()
        csv_training_writers = dict()
        csv_validation_writers = dict()
        fieldnames = self.cfg["csv_fieldnames"]
        for dataset_type in ['training', 'validation']:
            if not os.path.exists(os.path.join(self.cfg["dataset_output_dir"], dataset_type)):
                os.mkdir(os.path.join(self.cfg["dataset_output_dir"], dataset_type))
        for label in ['cpu', 'network', 'memory', 'all']:
            pcap_validation_writers[label] = PcapWriter(os.path.join(self.cfg["dataset_output_dir"], 'validation', f'{label}.pcap'), append=True)
            # with open(os.path.join(self.cfg["dataset_output_dir"], 'training', f'{label}.csv')) as f:
            csv_training_file = open(os.path.join(self.cfg["dataset_output_dir"], 'training', f'{label}.csv'), 'w')
            csv_training_writers[label] = csv.DictWriter(csv_training_file, fieldnames=fieldnames)
            csv_validation_file = open(os.path.join(self.cfg["dataset_output_dir"], 'validation', f'{label}.csv'), 'w')
            csv_validation_writers[label] = csv.DictWriter(csv_validation_file, fieldnames=fieldnames)
        # Add csv file for all
        # csv_training_writers['all'] = csv.DictWriter(open(os.path.join(self.cfg["dataset_output_dir"], 'training', f'all.csv'), 'w'), fieldnames=fieldnames)
        # csv_validation_writers['all'] = csv.DictWriter(open(os.path.join(self.cfg["dataset_output_dir"], 'validation', f'all.csv'), 'w'), fieldnames=fieldnames)
        csv_validation_writers['all'].writeheader()
        for dir in os.listdir(self.cfg["pcap_dataset_main_dir"]):
            self.club_pcaps(
                os.path.join(os.path.abspath(self.cfg["pcap_dataset_main_dir"]), dir),
                self.cfg['app_categories'][dir],
                pcap_validation_writers,
                csv_training_writers,
                csv_validation_writers)
        csv_training_file.close()
        csv_validation_file.close()
        # self.output_simple_dataset()

    def load_generated_dataset(self):
        # Create a generated dataset
        # self.generated_dataset = {
        #     str(cat): [] for cat in set(self.cfg["app_categories"].values())}
        # with open(self.cfg["generated_dataset"], 'r') as f:
        #     reader = csv.DictReader(f)
        #     # Skip the header
        #     next(reader)
        #     for row in reader:
        #         self.generated_dataset[row['category']].append(row)
        POSSIBLE_PRIORITY = range(8)
        POSSIBLE_CATEGORY = range(8)
        POSSIBLE_PERMISSIONS = range(4)
        POSSIBLE_TIQ = range(0, 14)
        POSSIBLE_TOD = range(4)
        # POSSIBLE_POWER = range(8)
        # This will hold generated datasets queried by their 
        self.generated_dataset = {category_num: [] for category_num in POSSIBLE_CATEGORY}
        print(self.generated_dataset)
        for row in itertools.product(POSSIBLE_CATEGORY, POSSIBLE_PERMISSIONS, POSSIBLE_PRIORITY, POSSIBLE_TIQ, POSSIBLE_TOD):
            # Algorithm to determine ranking
            # Note that this now includes network intensive
            row = {
                'category': row[0],
                'permissions': row[1],
                'priority': row[2],
                'tiq': row[3],
                'tod': row[4],
                'power': random.choice(self.cfg["power_consumption_ranges_by_category"][f"{row[0]}"]),
                'cpu': 0,
                'network': 0,
                'memory': 0
            }
            # Permissions: 1: CPU, 2: network, 3: memory, 0: unknown
            if row['permissions'] != 0:
                if row['permissions'] == 1:
                    row['cpu'] = 1
                elif row['permissions'] == 2:
                    row['network'] = 1
                else:
                    row['memory'] = 1
            # Priority: greater than 4 gets CPU
            elif row['priority'] > 4:
                row['cpu'] = 1
            # Priority greater than 2 gets network
            elif row['priority'] > 2:
                row['network'] = 1
            elif row['category'] != 0:
                # SPEEDY TASKS -> Network
                # audio, web, content marketplaces, social media
                # PROCESS INTENSIVE TASKS -> CPU
                # Gaming, 
                # LARGE FILE SIZES (Not fast) -> Memory
                # Video, File Sharing
                if row['category'] in [2, 4, 5, 7]:
                    row['network'] = 1
                # Gaming -> CPU
                elif row['category'] in [3]:
                    row['cpu'] = 1
                else:
                    row['memory'] = 1
            elif row['tiq'] > 2:
                row['network'] = 1
            # If the time of day is in the last segment, prefer to send to
            # memory server (to keep network more open to higher priority)
            elif row['tod'] == 3:
                row['memory'] = 1
            # If it falls through, packet length will be used
            # Now add this to the proper list in the dataset
            self.generated_dataset[row['category']].append(row)

    def club_pcaps(self, pcap_dir, category, pcap_validation_writers, csv_training_writers, csv_validation_writers):
        """Function to pull in pcap data from all pcaps in
        a directory and then output a modified pcap combining everything"""
        print("Looking in", pcap_dir)
        # Allow user to specify if a PCAP should be generated
        gen_pcap_output = self.cfg["create_modified_pcap"]
        # generated_dataset_iter = itertools.cycle(self.generated_dataset[category])
        for f in absoluteFilePaths(pcap_dir):
            # if f == training_output_file or f == validation_output_file:
            #     continue
            reader = PcapReader(f)
            for i, pkt in enumerate(reader):
                # Place every 5th packet in validation bin
                if self.cfg["max_packets_per_file"] < 0 or i >= self.cfg["max_packets_per_file"]:
                    break
                # Clear line
                print("", end='\r')
                print(f"working on packet {i}", end='\r')
                is_validation = (i % 5 == 0)
                generated_datapoint = copy.copy(random.choice(self.generated_dataset[category]))
                while not isinstance(pkt, NoPayload):
                    if isinstance(pkt, (IP)):
                        """This will club together a packet from the PCAP with a generated datapoint
                        and write the output to both the PCAP and CSV file"""
                        generated_datapoint['packet_length'] = getattr(pkt, 'len')
                        # Change to the destination IP address
                        # timestamp = FIXED_EPOCH_TIME - int(generated_datapoint["tiq"])
                        if gen_pcap_output:
                            options = [
                                IPOption(b'\x1e\x03%1b' % (int(generated_datapoint['category']).to_bytes(1, 'big'))),
                                IPOption(b'\x5e\x03%1b' % ((int(int(generated_datapoint['tiq']) * 16) + int(generated_datapoint['tod'])).to_bytes(1, 'big'))),
                                IPOption(b'\x9e\x03%1b' % ((int(generated_datapoint['permissions']) * 16 + int(generated_datapoint['priority'])).to_bytes(1, 'big'))),
                                IPOption(b'\xde\x03%1b' % (int(generated_datapoint['power']).to_bytes(1, 'big'))),
                                IPOption(b'\x00'),
                            ]
                            setattr(pkt, 'options', options)
                            setattr(pkt, 'dst', self.cfg['destination_ip'])
                            del pkt['IP'].len
                            del pkt['IP'].chksum
                            del pkt['IP'].ihl
                        break
                    pkt = pkt.payload
                # Check if generated_datapoint has unknown label, if so use packet length
                if generated_datapoint['cpu'] == 0 and generated_datapoint['network'] == 0 and generated_datapoint['memory'] == 0:
                    if int(generated_datapoint['packet_length']) < self.cfg['length_threshold_cpu']:
                        generated_datapoint['network'] = 1
                    else:
                        generated_datapoint['memory'] = 1
                # del generated_datapoint['label']
                # separate out CSV 
                if generated_datapoint['memory'] == 1:
                    label = 'memory'
                elif generated_datapoint['network'] == 1:
                    label = 'network'
                elif generated_datapoint['cpu'] == 1:
                    label = 'cpu'
                else:
                    raise Exception("Cannot label!")
                csv_validation_writers[label].writerow(generated_datapoint) if is_validation else csv_training_writers[label].writerow(generated_datapoint)
                csv_validation_writers['all'].writerow(generated_datapoint) if is_validation else csv_training_writers['all'].writerow(generated_datapoint)
                # if is_validation:
                #     self.simple_dataset["validation"][label].append(generated_datapoint)
                # else:
                #     self.simple_dataset["training"][label].append(generated_datapoint)
                if gen_pcap_output and is_validation:
                    pcap_validation_writers[label].write(pkt)
                    pcap_validation_writers['all'].write(pkt)
                i += 1

    # def output_simple_dataset(self):
    #     if not os.path.exists(self.cfg["dataset_output_dir"]):
    #         os.mkdir(self.cfg["dataset_output_dir"])
    #     for dataset_type in ['training', 'validation']:
    #         if not os.path.exists(os.path.join(self.cfg["dataset_output_dir"], dataset_type)):
    #             os.mkdir(os.path.join(self.cfg["dataset_output_dir"], dataset_type))
    #         for label, data in self.simple_dataset[dataset_type].items():
    #             if len(data) == 0:
    #                 continue
    #             output_csv = os.path.join(
    #                 os.path.abspath(self.cfg["dataset_output_dir"]), dataset_type, str(label + '.csv'))
    #             with open(output_csv, 'w') as csvfile:
    #                 writer = csv.DictWriter(csvfile, fieldnames=list(data[0].keys()))
    #                 writer.writeheader()
    #                 for generated_datapoint in data:
    #                     writer.writerow(generated_datapoint)


@click.command()
@click.argument('cfgfile', default='./cfg_dataset_clubber.json')
def cli(cfgfile):
    # Start by reading cfg file
    if not os.path.exists(cfgfile):
        raise FileNotFoundError("Cannot find cfg file!")
    with open(cfgfile, 'r') as f:
        cfg = json.load(f)
    clubber = Clubber(cfg)


if __name__ == "__main__":
    cli()