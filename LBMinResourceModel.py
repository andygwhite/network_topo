import numpy as np


class LBMinResourceModel:
    """Object which mimics a scikit learn ML model which algorithmically
    load balances instead of using ML.
    Configurable using the lbalgo_cfg.json file. Can do absolute minimum or
    round robin with a max utilization cap"""
    def __init__(self, round_robin_cluster_mapping):
        self.round_robin_cluster_mapping = round_robin_cluster_mapping
        pass

    def predict(self, input_arr):
        """Receives a numpy array of a typical ML input. Want to return the
        server index which sits at the lowest utilization. Input is a 2d
        array with only one row"""
        return np.argmin(input_arr[0][12:])