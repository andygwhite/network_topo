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
        self.counter = 1

    def send_all_packets(self):
        """Use scapy to send all packets across
        the network."""
        for pkt in self.packets.values():
            print("attempting to send pkt", pkt)
            try:
                send(pkt)
            except OSError as err:
                print(f"[WARNING]: Couldn't send packet: {err}")
                time.sleep(0.01)
                continue
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
    def __init__(self, pcap_file):
        if not os.path.exists(pcap_file):
            raise FileNotFoundError("Could not find PCAP file!")
        self.reader_iter = iter(PcapReader(pcap_file))
        self.counter = 1

    def send_next_packet(self):
        try:
            pkt = next(self.reader_iter)
            send(pkt)
            print(self.counter)
            self.counter += 1
            return True
        except StopIteration:
            return False
        except OSError as oserr:
            print(f"[WARNING]: {oserr}")
            print(len(pkt))
            next(self.reader_iter)
            return True


@click.command
@click.argument("pcap_file")
@click.option("-d", "--delay", default=10)
def cli(pcap_file, delay):
    gen = PacketGeneratorPCAP(pcap_file)
    while gen.send_next_packet():
        time.sleep(delay/1000)
    exit()


if __name__ == "__main__":
    cli()