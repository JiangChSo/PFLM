#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Random.random import randint
from rfc_3526_groups import RFC_3526_GROUPS

class DHKE:

    def __init__(self, groupID=14):
        self.g = RFC_3526_GROUPS[groupID][0]
        self.p = RFC_3526_GROUPS[groupID][1]

    def get_params(self):
        return self.g, self.p

    def generate_keys(self):
        sk = randint(1, self.p - 1)
        pk = pow(self.g, sk, self.p)
        return sk, pk

    def agree(self, sk, pk):
        shared_key = pow(pk, sk, self.p)
        return shared_key
