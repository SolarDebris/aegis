from rage.log import aegis_log
#from rage.machine import Machine

import yaml

"""
This is the class that will read in a yaml object and be used to create  
the formula. This formula will be used for determining the control
flow of the exploitation.
"""
class Poker:

    """
    This will take in a yaml object and be
    used in the poker class.
    """
    def __init__(self,machine):
        self.formula = yaml.safe_load(open('./rage/formula.yaml'))["formula"]



