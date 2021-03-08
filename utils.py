#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class bcolors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def pretty_print(d, indent=0):
    print()
    for key, value in d.items():
        print('\t' * indent + str(key) + ':')
        if isinstance(value, dict):
            pretty_print(value, indent+1)
        else:
            print('\t' * (indent+1) + str(value))
        print()

# From int to hex string
def int_to_hex(i):
    return '{:02x}'.format(i)

# # From int to d- hex string
# def int_to_hex(i,d):
#     return "{0:0{1}x}".format(i,d)

# From hex string to int
def hex_to_int(s):
    return int(s, 16)


def print_info(msg, sid):
    print(bcolors.YELLOW + bcolors.BOLD + 'sid='+str(sid) + bcolors.ENDC + bcolors.YELLOW + ' -- ' + str(msg) + bcolors.ENDC)

def print_success(msg, sid):
    print(bcolors.GREEN + bcolors.BOLD + 'sid='+str(sid) + bcolors.ENDC + bcolors.GREEN + ' -- ' + str(msg) + bcolors.ENDC)

def print_failure(msg, sid):
    print(bcolors.RED + bcolors.BOLD + 'sid='+str(sid) + bcolors.ENDC + bcolors.RED + ' -- ' + str(msg) + bcolors.ENDC)
