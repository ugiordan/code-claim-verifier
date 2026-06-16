import os
import torch

def load_model(path):
    return torch.load(path)

def process(data):
    result = load_model(data)
    return result

def unused_endpoint():
    pass

tl = torch.load
indirect_call = tl

class ModelLoader:
    load = staticmethod(torch.load)
