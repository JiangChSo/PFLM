#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
from flask import Flask, render_template, request
from flask_socketio import SocketIO
import time


from utils import bcolors, pretty_print, print_info, print_success, print_failure

from shamir_secret_sharing import SecretSharer
from diffie_hellman import DHKE

import numpy as np
np.set_printoptions(suppress=True) # No scientific notation

import os
import sys


import json
from pypbc import *
from AggregateSignatures import IBAS

# add that to your application before your create your socketio object.
from engineio.payload import Payload

from total_size import total_size
#############################################################################################
# ValueError: Too many packets in payload after update to v3.10.0 (https://github.com/miguelgrinberg/python-engineio/issues/142)
# If big CPU work, use async_handlers = True, or just sio.start_background_task( function )
#############################################################################################


# @sio.on('connect')
def connect(): # also use request.environ???
    pass

# @sio.on('disconnect')
def disconnect():
    pass


# @sio.on('PUB_KEYS')
def handle_pubkeys(data):
    sending_client_sid = request.sid#io客户端的sid, socketio用此唯一标识客户端.

    # Check in which round the FSM is
    if SERVER_VALUES['ROUND'] != 0:
        print_failure('Too late to send public keys.', sending_client_sid)
        return False, 'Too late to send your public keys.' # If False, make this node drop (sio.disconnect()) in the client callback

    # Add public key cpk to Server Storage for this client SID
    try:
        SERVER_STORAGE.setdefault(sending_client_sid, {})['cpk'] = data['cpk']
    except:
        print_failure('Missing key cpk in client''s messsage.', sending_client_sid)
        return False, 'Missing key cpk in your message.'

    # Add public key spk to Server Storage for this client SID
    try:
        SERVER_STORAGE.setdefault(sending_client_sid, {})['spk'] = data['spk']
    except:
        print_failure('Missing key spk in client''s messsage.', sending_client_sid)
        return False, 'Missing key spk in your message.'

    # Logging message
    #print_success('Received public keys.', sending_client_sid)

    # Add this client SID in the list of active clients at round 0
    SERVER_VALUES['U0'].append(sending_client_sid)

    # No clients have dropped out so far, and this is the last client we're receiving the public keys from
    if len(set(SERVER_VALUES['U0'])) == INIT_NB_CLIENTS:
        SERVER_VALUES['BENCHMARK_TIME_ROUND_0_COMM'] = time.time() - SERVER_VALUES['starting_time_round_0']
        print('Received all pubkeys', SERVER_VALUES['BENCHMARK_TIME_ROUND_0_COMM'])

    # Acknowledgement message (to the client) that everything went fine
    return True, 'Public keys succesfully received by server.'


# @sio.on('ENC_MSGS')
def handle_encrypted_messages(round1clienttoservermessages):
    sending_client_sid = request.sid
    #print("round1clienttoservermessages",round1clienttoservermessages)
    #print("complete receive messages of sending_client_sid:",sending_client_sid)

    #test the message sent by clients in round 1
    #print("round1clienttoservermessages:",round1clienttoservermessages)    #success 10.10

    #construct sessionID
    SERVER_VALUES['sessionID'].append([sending_client_sid, round1clienttoservermessages['Rn']])

    # Check in which round the FSM is
    if SERVER_VALUES['ROUND'] != 1:
        print_failure('Too late to send list of encrypted messages.', sending_client_sid)
        return False, 'Too late to send your list encrypted messages.' # If False, make this node drop (sio.disconnect()) in the client callback

    # TODO: Verify assumptions about this list and about sending_client_sid
    # Add the list of encrypted messages from this client SID to the Server Storage
    ##########################################
    SERVER_STORAGE[sending_client_sid]['list_enc_msg'] = round1clienttoservermessages["enc_msg"]
    #############################################

    # Logging message
    #print_success('Received list of encrypted messages.', sending_client_sid)

    # Add this client SID in the list of active clients at round 1
    SERVER_VALUES['U1'].append(sending_client_sid)

    # No clients from last round have dropped out, and this is the last client we're receiving the list of encrypted messages from
    if set(SERVER_VALUES['U1']) == set(SERVER_VALUES['U0']):
        SERVER_VALUES['BENCHMARK_TIME_ROUND_1_COMM'] = time.time() - SERVER_VALUES['starting_time_round_1']
        print('Received all encrypted msgs', SERVER_VALUES['BENCHMARK_TIME_ROUND_1_COMM'])

    # Acknowledgement message (to the client) that everything went fine
    return True, 'List of encrypted messages succesfully received by server.'


# @sio.on('INPUT_Y')
def handle_y(round2clienttoservermessages):
    sending_client_sid = request.sid

    #store the messages received from clients
    SERVER_STORAGE[sending_client_sid]['round2clienttoservermessages'] = round2clienttoservermessages

    # Check in which round the FSM is
    if SERVER_VALUES['ROUND'] != 2:
        print_failure('Too late to send masked input "y".', sending_client_sid)
        return False, 'Too late to send your masked input "y".'  # If False, make this node drop (sio.disconnect()) in the client callback

    # TODO: Verify assumptions about this y (format etc...)
    # Add the masked input y from this client SID to the Server Storage
    ############################################################
    SERVER_STORAGE[sending_client_sid]['y'] = round2clienttoservermessages["mask_x"]
    ############################################################

    # Logging message
    #print_success('Received masked input "y".', request.sid)

    # Add this client SID in the list of active clients at round 2
    SERVER_VALUES['U2'].append(sending_client_sid)

    # No clients from last round have dropped out, and this is the last client we're receiving the masked input y from
    #10.15 when note the communication cost of round 2 when clients dropping out,
    #we should let the condition len(SERVER_VALUES['U2']) == constant ,where constant = N *( 1 - drop_out)
    #modify for drouout
    #if set(SERVER_VALUES['U2']) == set(SERVER_VALUES['U1']):
    if len(SERVER_VALUES['U2']) == int(len(SERVER_VALUES['U1'])*(1 - dropout)):
        SERVER_VALUES['BENCHMARK_TIME_ROUND_2_COMM'] = time.time() - SERVER_VALUES['starting_time_round_2']
        print('Received all inputs y', SERVER_VALUES['BENCHMARK_TIME_ROUND_2_COMM'])

    # Acknowledgement message (to the client) that everything went fine
    return True, 'Masked input "y" succesfully received by server.'



# @sio.on('SHARES')
def handle_shares(shares):
    sending_client_sid = request.sid

    # Check in which round the FSM is
    if SERVER_VALUES['ROUND'] != 3:
        print_failure('Too late to send final shares.', sending_client_sid)
        return False, 'Too late to send your mask and shares.'  # If False, make this node drop (sio.disconnect()) in the client callback

    # TODO: Verify assumptions about this y (format etc...)
    # Add the shares from this client SID to the Server Storage
    ####################################################################################
    SERVER_STORAGE[sending_client_sid]['b_shares_alive'] = shares['b_shares_alive']
    SERVER_STORAGE[sending_client_sid]['ssk_shares_dropped'] = shares['ssk_shares_dropped']


    ####################################################################################

    # Logging message
    #print_success('Received share of mask "b" for alive clients and share of key "ssk" for dropped out clients.', request.sid)

    # Add this client SID in the list of active clients at round 3
    SERVER_VALUES['U3'].append(sending_client_sid)

    # No clients from last round have dropped out, and this is the last client we're receiving the masked input y from

    if set(SERVER_VALUES['U3']) == set(SERVER_VALUES['U2']):
        SERVER_VALUES['BENCHMARK_TIME_ROUND_3_COMM'] = time.time() - SERVER_VALUES['starting_time_round_3']
        print('Received all shares/masks', SERVER_VALUES['BENCHMARK_TIME_ROUND_3_COMM'])

    return True, 'Shares succesfully received by server.'

def handle_client_time(client_time_size):
    
    #print(client_time)

    SERVER_VALUES['clientround0time'].append(client_time_size['timeofround0'])
    SERVER_VALUES['clientround1time'].append(client_time_size['timeofround1'])
    SERVER_VALUES['clientround2time'].append(client_time_size['timeofround2'])
    SERVER_VALUES['clientround3time'].append(client_time_size['timeofround3'])
    SERVER_VALUES['clientround4time'].append(client_time_size['timeofround4'])
    SERVER_VALUES['clientround0totalsize'].append(client_time_size['clientround0totalsize'])
    SERVER_VALUES['clientround1totalsize'].append(client_time_size['clientround1totalsize'])
    SERVER_VALUES['clientround2totalsize'].append(client_time_size['clientround2totalsize'])
    SERVER_VALUES['clientround3totalsize'].append(client_time_size['clientround3totalsize'])


    return True, "successffle receive client time "


############# ROUND 0 ##############
### RECEIVE PUBLIC KEYS FROM ALL ###
###  CLIENTS AND BROADCAST THEM  ###
####################################

def timer_round_0():
    SERVER_VALUES['U0'] = []
    SERVER_VALUES['starting_time_round_0'] = time.time()
    print(bcolors.BOLD + 'Timer Round 0 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_0) # The execution of THIS function will be hang here for TIMEOUT_ROUND_0 seconds
    print(bcolors.BOLD + 'Timer Round 0 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 1  # Enter Round1 in the FSM

    # For benchmarking purpose...
    if not 'BENCHMARK_TIME_ROUND_0_COMM' in SERVER_VALUES:
        SERVER_VALUES['BENCHMARK_TIME_ROUND_0_COMM'] = TIMEOUT_ROUND_0
    start = time.time()
    round0()                    # Process Round0 server logic
    stop = time.time()
    SERVER_VALUES['BENCHMARK_TIME_ROUND_0_COMP'] = stop - start
    print('Processing Round0 done', SERVER_VALUES['BENCHMARK_TIME_ROUND_0_COMP'])


def round0():

    U0 = SERVER_VALUES['U0']
    n0 = len(U0)
    print("|U0| the number of clients sending public key:",n0)
    if n0 < 2: # At least 3 clients (n=3, t=2)
        print_failure('Did not receive public keys from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

    SERVER_VALUES['n0'] = n0
    SERVER_VALUES['t'] = int(n0/2) + 1

    list_pubkeys = {} # Copy here the cpk and spk keys for each client, don't send the WHOLE server storage dict
    for client_sid in U0:
        list_pubkeys[client_sid] = {}
        list_pubkeys[client_sid]['cpk'] = SERVER_STORAGE[client_sid]['cpk']
        list_pubkeys[client_sid]['spk'] = SERVER_STORAGE[client_sid]['spk']

    #print()
    #print_info('Broadcasting list of pubkeys to clients.', 'Server')
    #print()

    SERVER_VALUES['serverround0totalsize'] = total_size(list_pubkeys)

    sio.emit('ROUND_1', list_pubkeys) # No callback because it's a broadcast message (room=/)
    sio.start_background_task(timer_round_1)###############################开始等待下一轮




################ ROUND 1 #################
### RECEIVE LIST OF ENCRYPTED MESSAGES ###
### FROM ALL CLIENTS AND FORWARD THEM  ###
##########################################

def timer_round_1():
    SERVER_VALUES['U1'] = []

    SERVER_VALUES['sessionID'] = []

    SERVER_VALUES['starting_time_round_1'] = time.time()
    print(bcolors.BOLD + 'Timer Round 1 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_1)
    print(bcolors.BOLD + 'Timer Round 1 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 2  # Enter Round2 in the FSM

    # For benchmarking purpose...
    if not 'BENCHMARK_TIME_ROUND_1_COMM' in SERVER_VALUES:
        SERVER_VALUES['BENCHMARK_TIME_ROUND_1_COMM'] = TIMEOUT_ROUND_1
    start = time.time()
    round1()                    # Process Round1 server logic
    stop = time.time()
    SERVER_VALUES['BENCHMARK_TIME_ROUND_1_COMP'] = stop - start
    print('Processing Round1 done', SERVER_VALUES['BENCHMARK_TIME_ROUND_1_COMP'])

def round1():
    U1 = SERVER_VALUES['U1']
    n1 = len(U1)
    #print(U1)
    print("|U1| the number of clients sending enc mesage:",n1)
    #print(SERVER_VALUES['t'])
    if n1 < SERVER_VALUES['t']:
        print_failure('Did not receive encrypted messages from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

    # The "dropped out clients" are all the clients sid that were present in the set U0 but not in U1
    dropped_out_clients = list( set(SERVER_VALUES['U0']) - set(U1) )
    SERVER_VALUES['dropped_out_clients_round_1'] = dropped_out_clients

    # Instead of having a dictionary of messages FROM a given client SID, we want to construct
    # a dictionary of messages TO a given client SID.
    list_enc_msg_FROM = {}
    for client_sid in U1:
        list_enc_msg_FROM[client_sid] = SERVER_STORAGE[client_sid]['list_enc_msg']

    # This is here that we reverse the "FROM key TO value" dict to a "FROM value TO key" dict
    # e.g: {1: {2:a, 3:b, 4:c}, 3: {1:d,2:e,4:f}, 4: {1:g,2:h,3:i}}  -->  {1: {3:d, 4:g}, 3:{1:b, 4:i}, 4: {1:c,3:f} }
    list_enc_msg_TO = {}
    for from_client_sid, enc_msg_from_client_sid in list_enc_msg_FROM.items():
        for to_client_sid, enc_msg_to_client_sid in enc_msg_from_client_sid.items():
            # print(from_client_sid + ' --> ' + to_client_sdropoutid + ' : ' + str(enc_msg_to_client_sid))
            list_enc_msg_TO.setdefault(to_client_sid, {})[from_client_sid] = enc_msg_to_client_sid

    #print_info('Forwarding lists of encrypted messages to all clients.', 'Server')

    sessionID = SERVER_VALUES['sessionID']
    #print("sessionID------->",sessionID)

    serverround1totalsize = 0
    for client_sid in U1:
        round1servertoclientmessages = {"SID":sessionID, "enc_msgs":list_enc_msg_TO[client_sid]}
        serverround1totalsize += total_size(round1servertoclientmessages)
        sio.emit('ROUND_2',round1servertoclientmessages , room=client_sid)
    SERVER_VALUES['serverround1totalsize'] = serverround1totalsize #单播 逐个相加
    sio.start_background_task(timer_round_2)





######################## ROUND 2 ###########################
### RECEIVE MASKED INPUTS FROM ALL CLIENTS AND ADVERTISE ###
###   ABOUT THE DROPPED OUT CLIENTS FROM LAST ROUND      ###
############################################################

def timer_round_2():
    SERVER_VALUES['U2'] = []
    SERVER_VALUES['starting_time_round_2'] = time.time()
    print(bcolors.BOLD + 'Timer Round 2 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_2)
    print(bcolors.BOLD + 'Timer Round 2 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 3  # Enter Round3 in the FSM (does not accept masked inputs "y" from clients anymore)

    # For benchmarking purpose...
    if not 'BENCHMARK_TIME_ROUND_2_COMM' in SERVER_VALUES:
        SERVER_VALUES['BENCHMARK_TIME_ROUND_2_COMM'] = TIMEOUT_ROUND_2
    start = time.time()
    round2()                    # Process Round2 server logic
    stop = time.time()
    SERVER_VALUES['BENCHMARK_TIME_ROUND_2_COMP'] = stop - start
    print('Processing Round2 done', SERVER_VALUES['BENCHMARK_TIME_ROUND_2_COMP'])

def round2():

    U2 = SERVER_VALUES['U2']
    n2 = len(U2)
    print("|U2| the number of clients sending inputs y:",n2)
    if n2 < SERVER_VALUES['t']:
        print_failure('Did not receive masked input "y" from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

    # The "dropped out clients" are all the clients sid that were present in the set U1 but not in U2
    dropped_out_clients = list( set(SERVER_VALUES['U1']) - set(U2) )
    SERVER_VALUES['dropped_out_clients_round_2'] = dropped_out_clients

    #print()
    #print_info('Advertise list of alive and dropped out clients from the previous round to all still alive clients.', 'Server')
    #print()

    round2servertoclientmessages = []
    for client_sid in U2:
        round2clienttoservermessages = SERVER_STORAGE[client_sid]['round2clienttoservermessages']
        round2servertoclientmessages.append(round2clienttoservermessages)


    SERVER_VALUES['serverround2totalsize'] = total_size({'dropped_out': dropped_out_clients, 'alive': U2,'round2servertoclientmessages':round2servertoclientmessages}) 
    sio.emit('ROUND_3', {'dropped_out': dropped_out_clients, 'alive': U2,'round2servertoclientmessages':round2servertoclientmessages})

    sio.start_background_task(timer_round_3)





#################### ROUND 3 #########################
### RECEIVE ALL NECESSARY INFORMATION FROM CLIENTS ###
###     TO RECONSTRUCT AGGREGATED OUTPUT Z         ###
######################################################

def timer_round_3():
    SERVER_VALUES['U3'] = []
    SERVER_VALUES['starting_time_round_3'] = time.time()
    print(bcolors.BOLD + 'Timer Round 3 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_3)
    print(bcolors.BOLD + 'Timer Round 3 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 4  # Enter Round4 in the FSM (does not accept masks from clients anymore)

    # For benchmarking purpose...
    if not 'BENCHMARK_TIME_ROUND_3_COMM' in SERVER_VALUES:
        SERVER_VALUES['BENCHMARK_TIME_ROUND_3_COMM'] = TIMEOUT_ROUND_3
    start = time.time()
    round3()                    # Process Round3 server logic
    stop = time.time()
    SERVER_VALUES['BENCHMARK_TIME_ROUND_3_COMP'] = stop - start

    TOTAL_TIME = time.time() - START_TIME
    #10.16 modify the total time the actual communication time of the server
    TOTAL_TIME = TOTAL_TIME - TIMEOUT_ROUND_0 - TIMEOUT_ROUND_1 - TIMEOUT_ROUND_2 - TIMEOUT_ROUND_3 + SERVER_VALUES['BENCHMARK_TIME_ROUND_0_COMM'] + SERVER_VALUES['BENCHMARK_TIME_ROUND_1_COMM'] + SERVER_VALUES['BENCHMARK_TIME_ROUND_2_COMM'] + SERVER_VALUES['BENCHMARK_TIME_ROUND_3_COMM']
    SERVER_VALUES['TOTAL_TIME'] = TOTAL_TIME

    print('Processing Round3 done', SERVER_VALUES['BENCHMARK_TIME_ROUND_3_COMP'])


def round3():

    U3 = SERVER_VALUES['U3']
    n3 = len(U3)
    print("|U3| the number of clients sending shared masks:",n3)
    if n3 < SERVER_VALUES['t']:
        print_failure('Did not receive masks and shares from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

    # The "dropped out clients" are all the clients sid that were present in the set U2 but not in U3
    dropped_out_clients = list( set(SERVER_VALUES['U2']) - set(U3) )
    SERVER_VALUES['dropped_out_clients_round_3'] = dropped_out_clients

    Z = 0
    
    print("NB DROPPED OUT CLIENTS =", len(SERVER_VALUES['dropped_out_clients_round_2']))
    if SERVER_VALUES['dropped_out_clients_round_2'] != []:

        # Retrieve the shares of "ssk" of dropped out clients from all alive clients
        all_ssk_shares = []
        for client_sid in U3:
            all_ssk_shares.append(SERVER_STORAGE[client_sid]['ssk_shares_dropped'])

        ssk_shares_for_sid = {
            k: [d.get(k) for d in all_ssk_shares]
            for k in set().union(*all_ssk_shares)
        }

        # Reconstruct ssk from its shares
        ssk_for_sid = {}
        for client_sid in SERVER_VALUES['dropped_out_clients_round_2']:
            ssk = SecretSharer.recover_secret( ssk_shares_for_sid[client_sid] )
            ssk_for_sid[client_sid] = ssk

        # Reconstruct all blinding values (s_masks) for all pairs of alive users with the dropped out users
        all_masks = np.zeros(NB_CLASSES)
        for dropped_client_sid in SERVER_VALUES['dropped_out_clients_round_2']:
            for alive_client_sid in U3:
                s_for_sid = DHKE.agree(ssk_for_sid[dropped_client_sid], SERVER_STORAGE[alive_client_sid]['spk'])
                np.random.seed(s_for_sid % 2**32)
                s_mask_for_sid = np.random.uniform(-UNIFORM_S_BOUNDS, UNIFORM_S_BOUNDS, NB_CLASSES)
                sgn = np.sign(int(alive_client_sid, 16) - int(dropped_client_sid, 16))
                all_masks += sgn * s_mask_for_sid

        Z -= all_masks


    # Retrieve the shares of "b" from all alive clients
    all_b_shares = []
    for client_sid in U3:
        all_b_shares.append(SERVER_STORAGE[client_sid]['b_shares_alive'])

    b_shares_for_sid = {
        k: [d.get(k) for d in all_b_shares]
        for k in set().union(*all_b_shares)
    }

    # Reconstruct "b" from its shares
    b_for_sid = {}
    for client_sid in U3:
        b = SecretSharer.recover_secret(  b_shares_for_sid[client_sid] )
        b_for_sid[client_sid] = b

    # Remove b from the y that we received from clients, and aggregate the whole
    for client_sid in U3:
        b = b_for_sid[client_sid]
        np.random.seed(b)
        b_mask = np.random.uniform(-UNIFORM_B_BOUNDS, UNIFORM_B_BOUNDS, NB_CLASSES)
        Z += (SERVER_STORAGE[client_sid]['y'] - b_mask)

    print('Server succesfully aggregate the result and the lenth is ',len(list(Z)))

    # For Decentralized PATE, the label would be the argmax of this vote vector
    #print('LABEL:', np.argmax(Z))

    SERVER_VALUES['serverround3totalsize'] = total_size({"aggregation":list(Z),'U3':U3})

    sio.emit('ROUND_4', {"aggregation":list(Z),'U3':U3}) #tianjia in 10.11

    
    # Go back to function call (ret) and exit in function timer_round3() above
    sio.start_background_task(timer_round_4)

def timer_round_4():
    SERVER_VALUES['clientround0time'] = []
    SERVER_VALUES['clientround1time'] = []
    SERVER_VALUES['clientround2time'] = []
    SERVER_VALUES['clientround3time'] = []
    SERVER_VALUES['clientround4time'] = []
    SERVER_VALUES['clientround0totalsize'] = []
    SERVER_VALUES['clientround1totalsize'] = []
    SERVER_VALUES['clientround2totalsize'] = []
    SERVER_VALUES['clientround3totalsize'] = []
    
    print(bcolors.BOLD + 'Timer Round 4 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_4)
    print(bcolors.BOLD + 'Timer Round 4 Ends' + bcolors.ENDC)

    aveclientround0time = 0
    aveclientround1time = 0
    aveclientround2time = 0
    aveclientround3time = 0
    aveclientround4time = 0

    aveclientround0size = 0
    aveclientround1size = 0
    aveclientround2size = 0
    aveclientround3size = 0
    num = len(SERVER_VALUES['clientround0time'])
    for i in range(num):
        aveclientround0time += SERVER_VALUES['clientround0time'][i]/num
        aveclientround1time += SERVER_VALUES['clientround1time'][i]/num
        aveclientround2time += SERVER_VALUES['clientround2time'][i]/num
        aveclientround3time += SERVER_VALUES['clientround3time'][i]/num
        aveclientround4time += SERVER_VALUES['clientround4time'][i]/num
        aveclientround0size += SERVER_VALUES['clientround0totalsize'][i]/num
        aveclientround1size += SERVER_VALUES['clientround1totalsize'][i]/num
        aveclientround2size += SERVER_VALUES['clientround2totalsize'][i]/num
        aveclientround3size += SERVER_VALUES['clientround3totalsize'][i]/num
        


    # This CSV file will hold the Benchmark results: the times for each round and the total time
    timestamp = int(time.time())

    if os.path.isfile(BENCHMARK_FILENAME):
        csv_file = open(BENCHMARK_FILENAME, mode='a')
        csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    else:
        csv_file = open(BENCHMARK_FILENAME, mode='w')
        # Write CSV Header
        csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(['Timestamp','ServerTotalTime', 'Timeouts',
                             'Round0Comm', 'Round0Comp', 'Round1Comm', 'Round1Comp',
                             'Round2Comm', 'Round2Comp', 'Round3Comm', 'Round3Comp',
                             'Round0totalsize','Round1totalsize','Round2totalsize','Round3totalsize',
                             'ClientTotalTime','clientround0time','clientround1time','clientround2time','clientround3time','clientround4time',
                             'clientround0totalsize','clientround1totalsize','clientround2totalsize','clientround3totalsize'])

    #10.16 modify the total time the actual communication time of the server
    TIMEOUTS = f'{TIMEOUT_ROUND_0}_{TIMEOUT_ROUND_1}_{TIMEOUT_ROUND_2}_{TIMEOUT_ROUND_3}'
    # Write these Benchmark results to the CSV file
    csv_row = [ timestamp,
                SERVER_VALUES['TOTAL_TIME'],
                TIMEOUTS,
                SERVER_VALUES['BENCHMARK_TIME_ROUND_0_COMM'],
                SERVER_VALUES['BENCHMARK_TIME_ROUND_0_COMP'],
                SERVER_VALUES['BENCHMARK_TIME_ROUND_1_COMM'],
                SERVER_VALUES['BENCHMARK_TIME_ROUND_1_COMP'],
                SERVER_VALUES['BENCHMARK_TIME_ROUND_2_COMM'],
                SERVER_VALUES['BENCHMARK_TIME_ROUND_2_COMP'],
                SERVER_VALUES['BENCHMARK_TIME_ROUND_3_COMM'],
                SERVER_VALUES['BENCHMARK_TIME_ROUND_3_COMP'],
                SERVER_VALUES['serverround0totalsize'],
                SERVER_VALUES['serverround1totalsize'],
                SERVER_VALUES['serverround2totalsize'],
                SERVER_VALUES['serverround3totalsize'],
                aveclientround0time +aveclientround1time +aveclientround2time +aveclientround3time+aveclientround4time,
                aveclientround0time,
                aveclientround1time,
                aveclientround2time,
                aveclientround3time,
                aveclientround4time,
                aveclientround0size,
                aveclientround1size,
                aveclientround2size,
                aveclientround3size]
    csv_writer.writerow(csv_row)
    csv_file.close()
    
    sio.emit('complete', 'Reconstructed output z!')   #zhushi in 10.11

    sio.sleep(1)
    os._exit(0) # sio.stop()



if __name__ == '__main__':
    #ajust the max_decode_packets default 16
    Payload.max_decode_packets = 500
    #In practice : should adjust the dropout for experimental purposes 
    dropout = 0

    # In practice: should ajust these timeouts to the appropriate RTT
    timeout = 40
    TIMEOUT_ROUND_0 = 10
    TIMEOUT_ROUND_1 = 40
    TIMEOUT_ROUND_2 = 60
    TIMEOUT_ROUND_3 = timeout
    TIMEOUT_ROUND_4 = timeout

    # Global constants
    DO_GLOBAL_LOGGING = False
    NB_CLASSES = 100 # Need to know this to appropriately size our arrays
    UNIFORM_B_BOUNDS = 1e6 # Min and Max bounds for random b masking values
    UNIFORM_S_BOUNDS = 1e6 # Min and Max bounds for random s masking values

    # 2 sorts of measurements per round, COMMunication time, with the clients
    # and COMPutation time (only the server, processing the logic for this round)
    # Stored in SERVER_VALUES dict, as:
    # SERVER_VALUES['BENCHMARK_TIME_ROUND_i_COMP'] or SERVER_VALUES['BENCHMARK_TIME_ROUND_i_COMM']

    assert(len(sys.argv) == 3)
    INIT_NB_CLIENTS = int(sys.argv[1])
    BENCHMARK_FILENAME = sys.argv[2]

    # Initialization of the parameters (groupID 14) for the Diffie-Hellman
    # Key Exchange algorithm
    global DHKE
    DHKE = DHKE(groupID=14)

    # This dictionary will contain all the values used by the server
    # to keep track of time, rounds, and number of clients
    global SERVER_VALUES
    SERVER_VALUES = {}

    # This dictionary will contain the information that the server
    # received about all clients. It is keyed by client_sid.
    global SERVER_STORAGE
    SERVER_STORAGE = {}

    # Global variable "ROUND" tracking the Round Number --> Finite State Machine Logic of the server
    SERVER_VALUES['ROUND'] = 0

    app = Flask(__name__)
    sio = SocketIO(app, logger=DO_GLOBAL_LOGGING) # async_mode='eventlet' # recommended


    sio.on_event('connect', connect)
    sio.on_event('disconnect', disconnect)

    ############# ROUND 0 ##############
    ### RECEIVE PUBLIC KEYS FROM ALL ###
    ###  CLIENTS AND BROADCAST THEM  ###
    ####################################
    sio.on_event('PUB_KEYS', handle_pubkeys)   # TODO: Should be received and stored whenever the round

    ################ ROUND 1 #################
    ### RECEIVE LIST OF ENCRYPTED MESSAGES ###
    ### FROM ALL CLIENTS AND FORWARD THEM  ###
    ##########################################
    sio.on_event('ENC_MSGS', handle_encrypted_messages)

    ######################## ROUND 2 ###########################
    ### RECEIVE MASKED INPUTS FROM ALL CLIENTS AND ADVERTISE ###
    ###   ABOUT THE DROPPED OUT CLIENTS FROM LAST ROUND      ###
    ############################################################
    sio.on_event('INPUT_Y', handle_y)

    #################### ROUND 3 #########################
    ### RECEIVE ALL NECESSARY INFORMATION FROM CLIENTS ###
    ###     TO RECONSTRUCT AGGREGATED OUTPUT Z         ###
    ######################################################
    sio.on_event('SHARES', handle_shares)

    sio.on_event('client_time_size', handle_client_time)

    # Start the global timer for benchmarking purposes
    START_TIME = time.time()

    # Start the timer (timeout) for this round
    sio.start_background_task(timer_round_0)

    # TODO: Put address and port in a server.ini config file
    #sio.run(app, host='127.0.0.1', port=9876, debug=DO_GLOBAL_LOGGING)
    sio.run(app, host='127.0.0.1', port=8080, debug=DO_GLOBAL_LOGGING)
