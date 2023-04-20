# Runs multiple experiments at once
# References multiple_exp_cfg.yaml for all of the options
import json
import yaml
import copy
import subprocess


def split_yaml_cfg(cfg):
    """Recursively splits every list item into multiple dicts with single
    elements, including lists"""
    all_split_dicts = []
    for k, v in cfg.items():
        if isinstance(v, list):
            for elem in v:
                tmp = copy.deepcopy(cfg)
                tmp[k] = elem
                all_split_dicts.append(tmp)
    return all_split_dicts


if __name__ == "__main__":
    with open("./multiple_exp_cfg.yaml",'r') as f:
        cfg = yaml.safe_load(f)
    # Split the yaml files into a list of dicts with all of the modified
    # cfg fields. Also split nested lists
    split_cfg = split_yaml_cfg(cfg)
    for modified_cfg in split_cfg:
        with open("./topo_cluster_cfg.json", 'r') as f:
            topo_cfg = json.load(f)
        for k, v in modified_cfg.items():
            topo_cfg[k] = v
        with open("./topo_cluster_cfg.json", 'w') as f:
            json.dump(topo_cfg, f, indent=6)
        controller_cmd = "ryu-manager --log-file ./ryu.log cluster_load_balancer.py".split(' ')
        topo_cmd = "sudo -E python3 cluster_topo.py -s".split(' ')
        subprocess.Popen(controller_cmd)
        subprocess.call(topo_cmd)
        subprocess.call("sudo mn -c".split(' '))
        