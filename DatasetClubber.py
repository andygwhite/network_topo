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

from scapy.all import PcapReader, PcapWriter, IP, IPOption, NoPayload
import click
import os
import json
import csv
import itertools
import copy

FIXED_EPOCH_TIME = 1667952000
MAX_PACKETS_PER_FILE = 2000

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
        # self.simple_dataset = {
        #     "training": {lbl: [] for lbl in self.cfg["output_dataset_labels"]},
        #     "validation": {lbl: [] for lbl in self.cfg["output_dataset_labels"]}}
        print("Generated dataset loaded")
        # Create Pcap writers
        pcap_training_writers = dict()
        pcap_validation_writers = dict()
        csv_training_writers = dict()
        csv_validation_writers = dict()
        fieldnames = self.cfg["csv_fieldnames"]
        for dataset_type in ['training', 'validation']:
            if not os.path.exists(os.path.join(self.cfg["dataset_output_dir"], dataset_type)):
                os.mkdir(os.path.join(self.cfg["dataset_output_dir"], dataset_type))
        for label in ['cpu', 'network', 'memory']:
            pcap_training_writers[label] = PcapWriter(os.path.join(self.cfg["dataset_output_dir"], 'training', f'{label}.pcap'), append=True)
            pcap_validation_writers[label] = PcapWriter(os.path.join(self.cfg["dataset_output_dir"], 'validation', f'{label}.pcap'), append=True)
            # with open(os.path.join(self.cfg["dataset_output_dir"], 'training', f'{label}.csv')) as f:
            csv_training_file = open(os.path.join(self.cfg["dataset_output_dir"], 'training', f'{label}.csv'), 'w')
            csv_training_writers[label] = csv.DictWriter(csv_training_file, fieldnames=fieldnames)
            csv_validation_file = open(os.path.join(self.cfg["dataset_output_dir"], 'validation', f'{label}.csv'), 'w')
            csv_validation_writers[label] = csv.DictWriter(csv_validation_file, fieldnames=fieldnames)
        # Add csv file for all
        csv_training_writers['all'] = csv.DictWriter(open(os.path.join(self.cfg["dataset_output_dir"], 'training', f'all.csv'), 'w'), fieldnames=fieldnames)
        csv_validation_writers['all'] = csv.DictWriter(open(os.path.join(self.cfg["dataset_output_dir"], 'validation', f'all.csv'), 'w'), fieldnames=fieldnames)
        for dir in os.listdir(self.cfg["pcap_dataset_main_dir"]):
            self.club_pcaps(
                os.path.join(os.path.abspath(self.cfg["pcap_dataset_main_dir"]), dir),
                str(self.cfg['app_categories'][dir]),
                pcap_training_writers,
                pcap_validation_writers,
                csv_training_writers,
                csv_validation_writers)
        csv_training_file.close()
        csv_validation_file.close()
        # self.output_simple_dataset()

    def load_generated_dataset(self):
        # Load the entire generated dataset into memory
        self.generated_dataset = {
            str(cat): [] for cat in set(self.cfg["app_categories"].values())}
        with open(self.cfg["generated_dataset"], 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.generated_dataset[row['category']].append(row)

    def club_pcaps(self, pcap_dir, category, pcap_training_writers, pcap_validation_writers, csv_training_writers, csv_validation_writers):
        """Function to pull in pcap data from all pcaps in
        a directory and then output a modified pcap combining everything"""
        print("Looking in", pcap_dir)
        # training_output_file = os.path.join(pcap_dir, "_training_modified.pcap")
        # validation_output_file = os.path.join(pcap_dir, "_validation_modified.pcap")
        gen_output = self.cfg["create_modified_pcap"]
        # if gen_output:
        #     training_writer = PcapWriter(training_output_file, append=True)
        #     validation_writer = PcapWriter(validation_output_file, append=True)
        generated_dataset_iter = itertools.cycle(self.generated_dataset[category])
        for f in absoluteFilePaths(pcap_dir):
            # if f == training_output_file or f == validation_output_file:
            #     continue
            reader = PcapReader(f)
            for i, pkt in enumerate(reader):
                # Place every 5th packet in validation bin
                if MAX_PACKETS_PER_FILE < 0 or i >= MAX_PACKETS_PER_FILE:
                    break
                print(f"working on packet {i}", end='\r')
                is_validation = (i % 5 == 0)
                dp = copy.copy(next(generated_dataset_iter))
                while not isinstance(pkt, NoPayload):
                    if isinstance(pkt, (IP)):
                        # Pull out packet length
                        dp['packet_length'] = getattr(pkt, 'len')
                        # Change to the destination IP address
                        timestamp = FIXED_EPOCH_TIME - int(dp["tiq"])
                        if gen_output:
                            options = [
                                IPOption(b'\x1e\x03%1b' % (int(dp['category']).to_bytes(1, 'big'))),
                                IPOption(b'\x5e\x03%1b' % ((int(int(dp['tiq']) / 3600 * 16) + int(dp['tod'])).to_bytes(1, 'big'))),
                                IPOption(b'\x9e\x03%1b' % ((int(dp['permissions']) * 16 + int(dp['priority'])).to_bytes(1, 'big'))),
                            ]
                            setattr(pkt, 'options', options)
                            setattr(pkt, 'dst', self.cfg['destination_ip'])
                            del pkt['IP'].len
                            del pkt['IP'].chksum
                            del pkt['IP'].ihl
                        break
                    pkt = pkt.payload
                # Check if dp has unknown label, if so use packet length
                if dp['cpu'] == '0' and dp['network'] == '0' and dp['memory'] == '0':
                    if int(dp['packet_length']) < self.cfg['length_threshold_cpu']:
                        dp['cpu'] = '1'
                    else:
                        dp['memory'] = '1'
                # del dp['label']
                # separate out CSV 
                label = 'cpu'
                if dp['memory'] == '1':
                    label = 'memory'
                elif dp['network'] == '1':
                    label = 'network'
                csv_validation_writers[label].writerow(dp) if is_validation else csv_training_writers[label].writerow(dp)
                csv_validation_writers['all'].writerow(dp) if is_validation else csv_training_writers['all'].writerow(dp)
                # if is_validation:
                #     self.simple_dataset["validation"][label].append(dp)
                # else:
                #     self.simple_dataset["training"][label].append(dp)
                if gen_output and is_validation:
                    pcap_validation_writers[label].write(pkt)
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
    #                 for dp in data:
    #                     writer.writerow(dp)


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