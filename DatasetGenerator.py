"""
Author: Andy White
This program shall generate a dummy dataset for testing with
the dataset clubber
"""

import click
import os
import json
import csv
import itertools
import copy

FIXED_EPOCH_TIME = 1668036116
POSSIBLE_PRIORITY = range(8)
POSSIBLE_CATEGORY = range(8)
POSSIBLE_PERMISSIONS = range(4)
POSSIBLE_TIQ = range(0, 14)
POSSIBLE_TOD = range(4)
# POSSIBLE_PACKET_LENGTH = range(50, 1400, 200)
@click.command()
def cli():
    with open('generated_dataset_DEMO.csv', 'w') as f:
        datawriter = csv.DictWriter(f, fieldnames=['category', 'permissions', 'priority', 'tiq', 'tod', 'network', 'memory', 'cpu'], delimiter=',', quotechar='|')
        datawriter.writeheader()
        for row in itertools.product(POSSIBLE_PERMISSIONS, POSSIBLE_PRIORITY, POSSIBLE_CATEGORY, POSSIBLE_TIQ, POSSIBLE_TOD):
             # Algorithm to determine ranking
            # Note that this now includes network intensive
            row = {
                'permissions': row[0],
                'priority': row[1],
                'category': row[2],
                'tiq': row[3],
                'tod': row[4],
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
            # This is applied in the DatasetClubber script
            datawriter.writerow(row)
    
        

if __name__ == "__main__":
    cli()