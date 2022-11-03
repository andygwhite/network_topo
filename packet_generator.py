# Script to manage generating and sending packets
# This will be controlled by a JSON configuration file

import os
import json
import click
from scapy.all import IP, IPOption, send, PcapReader
import time


IP_HEADER_FIELDS = ['src', 'dst', 'options']
class PacketGeneratorJSON():
    def __init__(self, cfg):
        self.cfg = cfg
        self.packets = {}
        self.load_packets()

    def send_all_packets(self):
        """Use scapy to send all packets across
        the network."""
        for pkt in self.packets.values():
            print("attempting to send pkt", pkt)
            send(pkt)
            return

    def load_packets_from_json(self):
        for pkt_name, pkt in self.cfg['packets'].items():
            self.packets[pkt_name] = self.create_ip_packet(pkt)

    def create_ip_packet(self, pkt):
        """Uses scapy to generate a scapy packet object
        Takes a dict with the IP header info specified
        and creates a scapy packet to match"""
        scapy_pkt = IP()
        for field_name, field_value in pkt.items():
            if field_name == 'options':
                scapy_pkt.options = [IPOption(bytearray(fv)) for fv in field_value]
            else:
                print("Setting", field_name)
                setattr(scapy_pkt, field_name, field_value)
        scapy_pkt.show()
        return scapy_pkt


class PacketGeneratorPCAP:
    def __init__(self, cfg):
        self.cfg = cfg
        if not os.path.exists(cfg["pcap_file"]):
            raise FileNotFoundError("Could not find PCAP file!")
        self.reader_iter = iter(PcapReader(cfg["pcap_file"]))

    def send_next_packet(self):
        try:
            send(next(self.reader_iter))
            return True
        except StopIteration:
            return False


@click.command
@click.argument("cfgfile", default='./traffic_cfg.json')
def cli(cfgfile):
    with open(cfgfile, 'r') as f:
        cfg = json.load(f)
    gen = PacketGeneratorPCAP(cfg)
    while gen.send_next_packet():
        time.sleep(cfg['delay']/1000)
    exit()


if __name__ == "__main__":
    cli()