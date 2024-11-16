from rage.log import aegis_log
#from rage.machine import Machine

import yaml

"""
This is the class that will generate
a formula on what steps are needed to pwn.
"""
class Poker:

    """
    This will take in a yaml object and be
    used in the poker class.
    """
    self.formula = yaml.load(open('formula.yaml'))

    def __init__(self):
        self.formula = yaml.load(open('formula.yaml'))



if __name__ == "__main__":

    poker = Poker()
    print(poker.formula)

