#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import random
import secrets
import sys
import time

import numpy as np

from AES_cs import PrpCrypt

np.set_printoptions(suppress=True) # No scientific notation

import socketio

from shamir_secret_sharing import SecretSharer
from diffie_hellman import DHKE

from AES_encryption import AESCipher


from utils import bcolors, pretty_print, int_to_hex, print_info, print_success, print_failure

from pypbc import *
from AggregateSignatures import IBAS
import hashlib
import json

from engineio.payload import Payload


from VElGamal import VEG

UNIFORM_B_BOUNDS = 1e6
UNIFORM_S_BOUNDS = 1e6

from total_size import total_size




#############################################################################################
# ValueError: Too many packets in payload after update to v3.10.0 (https://github.com/miguelgrinberg/python-engineio/issues/142)
# If big CPU work, use async_handlers = True, or just sio.start_background_task( function )
#############################################################################################


def server_ack(OK, msg):
    if OK:
        pass
        #print_success(msg, CLIENT_VALUES['my_sid'])
    else:
        print_failure(msg, CLIENT_VALUES['my_sid'])
        sio.disconnect()


# @sio.on('connect')
def connect():
    pass

# @sio.on('disconnect')
def disconnect():
    pass

# @sio.on('abort')
def abort(reason):
    print()
    print_failure(reason, 'Server')
    sio.disconnect()

# @sio.on('complete')
def complete(reason):
    #print()
    #print(bcolors.BOLD + bcolors.PURPLE + reason + bcolors.ENDC)
    sio.disconnect()



# @sio.on('START')
# def start(classification_task):
#     print('Task:')
#     print(classification_task)
#     sio.start_background_task(round0)



############# ROUND 0 ###############
### GENERATE AND SEND PUBLIC KEYS ###
#####################################

def round0():
    start = time.time()
    #print(bcolors.BOLD + '\n--- Round 0 ---' + bcolors.ENDC)

    # Generate the 2 pair of Diffie-Hellman keys
    # "s" will be used to generate the seed for the shared mask, and "c" the shared encryption key
    my_ssk, my_spk = DHKE.generate_keys()
    my_csk, my_cpk = DHKE.generate_keys()

    # Store the previously generated keys
    CLIENT_VALUES['my_ssk'] = my_ssk; CLIENT_VALUES['my_spk'] = my_spk
    CLIENT_VALUES['my_csk'] = my_csk; CLIENT_VALUES['my_cpk'] = my_cpk

    #generate IBAS key for client step1

    
    Un = CLIENT_VALUES['my_sid']

    P_n0,P_n1,sP_n0,sP_n1 = ibas.PKG(Un)
    #print("IBASkey:",sP_n01,sP_n11)

    #store IBAS key
    CLIENT_VALUES['P_n0'] = P_n0
    CLIENT_VALUES['P_n1'] = P_n1
    CLIENT_VALUES['sP_n0'] = sP_n0
    CLIENT_VALUES['sP_n1'] = sP_n1

    #generate VEG key for client step1
    k_n, Kn = veg.generate_keys()

    #store veg key
    CLIENT_VALUES['k_n'] = k_n
    CLIENT_VALUES['Kn'] = Kn
    #print("VEGkey:",k_n,Kn) #right 10.12


    # Send the client's public key for "c" and "s" to the server
    #print_info('Sending pubkeys to server...', CLIENT_VALUES['my_sid'])

    #print("daxiao:",total_size({'cpk':my_cpk, 'spk':my_spk}))#10.16 daxiao

    end = time.time()
    timeofround0 = end - start
    
    CLIENT_VALUES['timeofround0'] = timeofround0
    clientround0totalsize = total_size({'cpk':my_cpk, 'spk':my_spk})
    print("timeofround0:",timeofround0,"clientround0totalsize:",clientround0totalsize)

    CLIENT_VALUES['clientround0totalsize'] = clientround0totalsize
    sio.emit('PUB_KEYS', {'cpk':my_cpk, 'spk':my_spk}, callback=server_ack)



############### ROUND 1 ##################
###   RECEIVE PUBKEYS FROM EVERYONE,   ###
### GENERATE AND SEND ENCRYPTED SHARES ###
##########################################

# @sio.on('ROUND_1')
def round1_handler(pubkeys):
    #print(bcolors.BOLD + '\n--- Round 1 ---' + bcolors.ENDC)
    #print_success('Received public keys from server...', CLIENT_VALUES['my_sid'])
    sio.start_background_task(round1, pubkeys)

def round1(pubkeys):
    start = time.time()
    # Store the keys received from the server, in the dictionary CLIENT_STORAGE, for each client_sid
    for client_sid, pubkeys_for_client_sid in pubkeys.items():
        if client_sid == CLIENT_VALUES['my_sid']:
            continue # Does not need to store my own keys (already stored in CLIENT_VALUES)
        try:
            CLIENT_STORAGE.setdefault(client_sid, {})['cpk'] = pubkeys_for_client_sid['cpk']#当查找的键值 key 不存在的时候，setdefault()函数会返回默认值并更新字典，添加键值
            CLIENT_STORAGE.setdefault(client_sid, {})['spk'] = pubkeys_for_client_sid['spk']
        except KeyError:
            print_failure('Missing key cpk or spk in server''s messsage.', client_sid)
            sio.disconnect()

    # Compute n, the number of active clients (me, included)
    n = len(CLIENT_STORAGE.keys()) + 1                                                           #; print('n =', n)

    # Compute t, the minimum number of clients we need for the aggregation
    t = int(n/2) + 1                                                                             #; print('t =', t)

    

    # Draw random seed b, and make a mask out of it
    b = secrets.randbits(32)                                                                    #; print('b =', b)
    np.random.seed(b)
    b_mask = np.random.uniform(-UNIFORM_B_BOUNDS, UNIFORM_B_BOUNDS, NB_CLASSES)                 #; print('b_mask =', b_mask) # TODO: HOW TO CHOOSE THOSE VALUES???

    # Create t-out-of-n shares for seed b
    shares_b = SecretSharer.split_secret(b, t, n)                                               #; print('shares_b =', shares_b)

    # Create t-out-of-n shares for my private key my_ssk (as an hex_string)
    shares_my_ssk = SecretSharer.split_secret(CLIENT_VALUES['my_ssk'], t, n)                    #; print('shares_my_ssk =', shares_my_ssk)


    # Store all the previously generated values, in client's dictionary
    CLIENT_VALUES['n'] = n; CLIENT_VALUES['t'] = t

    
    CLIENT_VALUES['b'] = b; CLIENT_VALUES['b_mask'] = b_mask

    #CLIENT_VALUES['shares_a'] = shares_a
    CLIENT_VALUES['shares_b'] = shares_b
    CLIENT_VALUES['shares_my_ssk'] = shares_my_ssk

    # Store my share of b in isolation:
    my_share_b = shares_b[0]
    shares_b = list( set(shares_b) - set([my_share_b]) )
    CLIENT_VALUES['my_share_b'] = my_share_b

    list_encrypted_messages = {}
    for ID, client_sid in enumerate(CLIENT_STORAGE.keys()):

        if client_sid == CLIENT_VALUES['my_sid']:
            continue # Skip my own sid # FIXME: Actually, I am NOT part of CLIENT_STORAGE.keys()

        # Derive encryption key enc_key_for_sid (via Diffie-Hellman Agreement)
        enc_key_for_sid = DHKE.agree(CLIENT_VALUES['my_csk'], CLIENT_STORAGE[client_sid]['cpk'])             #; print('enc_key_for_sid =', enc_key_for_sid)

        # Client "client_sid" will be sent this message:
        msg = 'ProtoV1.0' + ' || ' + str(CLIENT_VALUES['my_sid']) + ' || ' + str(client_sid) + ' || ' + str(shares_my_ssk[ID]) + ' || ' + str(shares_b[ID])

        # Encrypt the message with the pre-derived shared encryption key
        enc_msg = PrpCrypt(str(enc_key_for_sid)).encrypt(msg)

        # Store the encrypted messages in a dictionary (keyed by client_sid) that will be sent to the server
        list_encrypted_messages[client_sid] = enc_msg


        CLIENT_STORAGE[client_sid]['enc_key'] = enc_key_for_sid
        CLIENT_STORAGE[client_sid]['msg'] = msg
        CLIENT_STORAGE[client_sid]['enc_msg'] = enc_msg

       

     #Generate Rn*************************************
    Rn = random.randint(1,1000)
    CLIENT_VALUES["Rn"] = Rn

    round1clienttoservermessages = {"Rn":Rn, "enc_msg":list_encrypted_messages}
    
    end = time.time()
    timeofround1 = end - start
    
    CLIENT_VALUES['timeofround1'] = timeofround1

    clientround1totalsize = total_size(round1clienttoservermessages)
    CLIENT_VALUES['clientround1totalsize'] = clientround1totalsize

    print("timeofround1:",timeofround1,"clientround1totalsize:",clientround1totalsize)

    sio.emit('ENC_MSGS', round1clienttoservermessages, callback=server_ack)
    # drop out in round 1 set(U1) - set(U0)

    if WILL_CRASH:
        sio.sleep(1)
        os._exit(0)


########### ROUND 2 ##############
### MASK AND SEND INPUT VECTOR ###
##################################

# @sio.on('ROUND_2')
def round2_handler(round1servertoclientmessages):
    #print(bcolors.BOLD + '\n--- Round 2 ---' + bcolors.ENDC)
    #print_success('Received list of encrypted messages for me from server...', CLIENT_VALUES['my_sid'])
    sio.start_background_task(round2, round1servertoclientmessages)
    # return True, 'List of encrypted messages succesfully received by client.', CLIENT_VALUES['my_sid'] # TODO: Acknowledgement is confusing in the logs

def round2(round1servertoclientmessages):
    #print("round1servertoclientmessages:",round1servertoclientmessages) success 10.10
    
    for client_sid, enc_msg in round1servertoclientmessages["enc_msgs"].items():

        # Decrypt the encrypted message and parse it
        enc_key_for_sid = CLIENT_STORAGE[client_sid]['enc_key']
        msg = PrpCrypt(str(enc_key_for_sid)).decrypt(enc_msg)

        msg_parts = msg.split(' || ')

        protocol_id = msg_parts[0] # TODO: What's the use? #TODO: Timestamp?
        from_client_sid = msg_parts[1]
        my_sid = msg_parts[2]
        share_ssk_for_sid = msg_parts[3]
        share_b_for_sid = msg_parts[4]

        # Store has been received for client_sid
        CLIENT_STORAGE[from_client_sid]['share_ssk'] = share_ssk_for_sid
        #CLIENT_STORAGE[from_client_sid]['share_a'] = share_a_for_sid
        CLIENT_STORAGE[from_client_sid]['share_b'] = share_b_for_sid

        # Sanity check
        if client_sid != from_client_sid or my_sid != CLIENT_VALUES['my_sid']:
            print_failure('Received wrong message!', CLIENT_VALUES['my_sid'])
            sio.disconnect()

        # Derive secret shared mask seed s_for_sid (Diffie-Hellman Agreement)
        s_for_sid = DHKE.agree(CLIENT_VALUES['my_ssk'], CLIENT_STORAGE[client_sid]['spk'])         #; print('s_for_sid =', s_for_sid)

        # Derive s_mask from above seed
        np.random.seed(s_for_sid % 2**32) # TODO: Higher entropy than 2**32??? (max value to .seed())
        s_mask_for_sid = np.random.uniform(-UNIFORM_S_BOUNDS, UNIFORM_S_BOUNDS, NB_CLASSES)                                  #; print('s_for_sid =', s_for_sid )# TODO: Which values??

        # Store also that
        CLIENT_STORAGE[client_sid]['s'] = s_for_sid
        CLIENT_STORAGE[client_sid]['s_mask'] = s_mask_for_sid


    # Construct masked input:
    yy = CLIENT_VALUES['x'] + CLIENT_VALUES['b_mask']

    #the second masked in our paper
    all_masks = np.zeros(NB_CLASSES)
    for client_sid in CLIENT_STORAGE.keys():
        if client_sid == CLIENT_VALUES['my_sid']:
            continue # Skip my own SID
        if not 's_mask' in CLIENT_STORAGE[client_sid].keys():
            print_failure("No shared mask for client", client_sid)
            continue # We do not have shared mask from this client SID
        sgn = np.sign(int(CLIENT_VALUES['my_sid'], 16) - int(client_sid, 16))  # Substract the masks of greater client SIDs,
        all_masks += sgn * CLIENT_STORAGE[client_sid]['s_mask']                # or add those of smaller client SIDs

    # Here is the final output "y" to send to server
    y = yy + all_masks

    '''
    Identity-Based Aggregate Signatures
    ->round0 & round 2 
    data:10.10
    '''
    '''individual signing step 2'''
    start = time.time()
    #extract sessionID from the message received from the server
    sessionID = round1servertoclientmessages['SID']
    #print("client receive SID",sessionID)
    
    #store the sessionID

    CLIENT_VALUES["sessionID"] = sessionID

    #calculate w by sessionID
    sha1 = hashlib.sha1()
    sha1.update(str(sessionID).encode("utf-8"))#str(sessionID) list ->string
    w = str(sha1.hexdigest())
    #w = "w" test first  
    #print("w->",w)

    P_n0 = CLIENT_VALUES['P_n0']
    P_n1 = CLIENT_VALUES['P_n1']
    sP_n0 = CLIENT_VALUES['sP_n0']
    sP_n1 = CLIENT_VALUES['sP_n1']

    Un = CLIENT_VALUES['my_sid']
    k_n = CLIENT_VALUES['k_n']
    Kn = CLIENT_VALUES['Kn']

    #VElGamal encryption
    x_n = []
    for i in range(NB_CLASSES):
        x_n.append(int(CLIENT_VALUES['x'][i]*1e6))

    #print("x_n",x_n)

    Cn = veg.enc(x_n,k_n)

    #construct Mn
    Mn= str(Kn)+str(Cn)+str(sessionID)
    sigma_n = ibas.InSign(w,Mn,Un,sP_n0,sP_n1)
    #print("Individual signature:", sigma_n)
    c_n = Element.from_hash(pairing, Zr, Un + Mn + w)

    #print("c_n",c_n,type(c_n))
    #print("P_n0",P_n0,type(P_n0))
    #print("P_n1",P_n1,type(P_n1))

    strsigma_n = [sigma_n[0],str(sigma_n[1]),str(sigma_n[2])] #shoud be convert to pypbc.Element.G2
    strc_n = str(c_n)#in fact it should by reconstruct though little computation cost
    strP_n0 = str(P_n0)
    strP_n1 = str(P_n1)

    round2clienttoservermessages = {"mask_x":list(y),"sigma_n":strsigma_n,"Cn":Cn,"Kn":Kn,"c_n":strc_n,"P_n0":strP_n0,"P_n1":strP_n1,'w':w}

    #print_info('Sending masked input "y" to server...', CLIENT_VALUES['my_sid'])
    end = time.time()
    timeofround2 = end - start
    CLIENT_VALUES['timeofround2'] = timeofround2
    clientround2totalsize = total_size(round2clienttoservermessages)
    CLIENT_VALUES['clientround2totalsize'] = clientround2totalsize

    print("timeofround2:",timeofround2,"clientround2totalsize:",clientround2totalsize)
    sio.emit('INPUT_Y', round2clienttoservermessages, callback=server_ack) # Send "y" as a python list because numpy arrays are not JSON-serializable


################ ROUND 3 ##################
### SEND SHARES OF B AND SSK, RESPECTIVELY FOR ALIVE AND DROPPED OUT CLIENTS ###
###########################################

# @sio.on('ROUND_3')
def round3_handler(dropped_out_clients):
    #print(bcolors.BOLD + '\n--- Round 3 ---' + bcolors.ENDC)
    #print_success('Received list of alive and dropped out clients from server...', CLIENT_VALUES['my_sid'])
    sio.start_background_task(round3, dropped_out_clients)

def round3(clients):
    start = time.time()
    clients['alive'].sort() # It is essential that all clients have the list in the same order (to select the noise parts to remove)


    #print("round3 messages from server:",clients)
    CLIENT_VALUES["round2servertoclientmessages"] = clients['round2servertoclientmessages']
    
    #print("round2servertoclientmessages for ibas verification:",CLIENT_VALUES["round2servertoclientmessages"]) #10.11

    dropped_out_clients = clients['dropped_out']
    alive_clients = list( set(clients['alive']) - set([CLIENT_VALUES['my_sid']]) ) # Except myself

    b_shares = {}
    for alive_client_sid in alive_clients:
        b_shares[alive_client_sid] = CLIENT_STORAGE[alive_client_sid]['share_b']
    b_shares[CLIENT_VALUES['my_sid']] = CLIENT_VALUES['my_share_b']

    ssk_shares = {}
    for dropped_client_sid in dropped_out_clients:
        ssk_shares[dropped_client_sid] = CLIENT_STORAGE[dropped_client_sid]['share_ssk']

    shares = {}
    shares['b_shares_alive'] = b_shares # Shares of "b" of alive clients
    shares['ssk_shares_dropped'] = ssk_shares # Shares of "ssk" of droppe
    # In practice: should ajust these timeouts to the appropriate RTT
    timeout = 70
    TIMEOUT_ROUND_0 = 10
    #print_info('Sending shares to server...', CLIENT_VALUES['my_sid'])

    end = time.time() #end time
    timeofround3 = end - start

    CLIENT_VALUES['timeofround3'] = timeofround3

    clientround3totalsize = total_size(shares)
    CLIENT_VALUES['clientround3totalsize'] = clientround3totalsize

    print("timeofround3:",timeofround3,"clientround3totalsize:",clientround3totalsize)

    sio.emit('SHARES', shares, callback=server_ack)


# @sio.on('ROUND_4')
def round4_handler(aggregationmessagez):
    sio.start_background_task(round4, aggregationmessagez)

def round4(aggregationmessagez):
    start = time.time()# start the time

    '''verify ibas'''

    round2servertoclientmessages = CLIENT_VALUES["round2servertoclientmessages"]

    #print("ibas yanzhengxiaoxi----->",round2servertoclientmessages) #10.11

    S_n_list = []
    T_n_list = []
    allMn = []
    allUn = aggregationmessagez["U3"]
    w = round2servertoclientmessages[0]['w']
    for i in round2servertoclientmessages:
        strsigma_n = i["sigma_n"]
        sigma_n = [strsigma_n[0], Element( pairing, G2, value = strsigma_n[1]), Element( pairing, G2, value = strsigma_n[2])]
        
        S_n_list.append(sigma_n[1])
        T_n_list.append(sigma_n[2])

        Mn = str(i['Kn']) + str(i['Cn'])+ str(CLIENT_VALUES["sessionID"])

        allMn.append(Mn)

    #Aggregation
    w,S_w,T_w = ibas.Aggre(w,S_n_list,T_n_list)

    #verification
    correctnessofIBAS = ibas.Verify(allUn,w,S_w,T_w,allMn)

    #print("the result of IBAS's verification: ",correctnessofIBAS) #10.16

    '''verify veg'''

    Kn_list = []
    Cn_list = []
    for i in round2servertoclientmessages:
        Kn = i['Kn']
        Kn_list.append(Kn)
        Cn = i['Cn']
        Cn_list.append(Cn)
    
    z_list = [] 
    for i in range(NB_CLASSES):
        z_list.append(int(aggregationmessagez["aggregation"][i]*1e6))
    #print("z_list:", z_list)
    correctnessofveg = veg.elverify(Kn_list,Cn_list, z_list)

    #print("the result of veg's verification: ",correctnessofveg)#10.16
    if(correctnessofIBAS&correctnessofveg == True):
        print(CLIENT_VALUES['my_sid'],"accept the aggregation! Verifing length:", len(allUn),'--',len(allMn))
        print("the results of IBAS's verification and veg's verification: ",True)
    else:
        print("the results of IBAS's verification and veg's verification: ",False)
    end = time.time() #end time
    timeofround4 = end - start
    print("timeofround4:",timeofround4)
    CLIENT_VALUES['timeofround4'] = timeofround4

    client_time_size = {'timeofround0':CLIENT_VALUES['timeofround0'],'timeofround1':CLIENT_VALUES['timeofround1'],
                        'timeofround2':CLIENT_VALUES['timeofround2'],'timeofround3':CLIENT_VALUES['timeofround3'],
                        'timeofround4':CLIENT_VALUES['timeofround4'],'clientround0totalsize':CLIENT_VALUES['clientround0totalsize'],
                        'clientround1totalsize':CLIENT_VALUES['clientround1totalsize'],'clientround2totalsize':CLIENT_VALUES['clientround2totalsize'],
                        'clientround3totalsize':CLIENT_VALUES['clientround3totalsize']}
    print('Processing Round4 done')
    #print(client_time)
    sio.emit('client_time_size', client_time_size, callback=server_ack)


################################################################################
################################################################################


if __name__ == '__main__':
    Payload.max_decode_packets = 500
    WILL_CRASH = False
    if len(sys.argv) > 1:
        if sys.argv[1] == 'crash':
            WILL_CRASH = True
        else:
            print('Unknown parameter:', sys.argv[1])

    NB_CLASSES = 100

    # This dictionary will contain all the values generated by this client
    # and used in the aggregation
    global CLIENT_VALUES
    CLIENT_VALUES = {}

    # This dictionary will contain all the values about the OTHER clients
    # part of the aggregation. It is keyed by client_sid.
    global CLIENT_STORAGE
    CLIENT_STORAGE = {}

    # The params of the group
    global DHKE
    DHKE = DHKE(groupID=14) # TODO: Use 2048-bit group (id=14) or above

    #The params of IBAS
    ibas = IBAS()
    pairing = ibas.pairing

    #The params of VEG
    veg = VEG()

    # The socketIO object representing our client's socket.
    # We can register listeners ('handlers') of events with the function sio.on(<event name>, <handler function>)
    sio = socketio.Client()

    # Connect this client to the server. Upon connection, this client receives a unique socket id "my_sid"
    # that we store in the CLIENT_VALUES
    #sio.connect('http://127.0.0.1:9876') # TODO: Put address and port in a server.ini config file
    sio.connect('http://127.0.0.1:8080')
    CLIENT_VALUES['my_sid'] = sio.eio.sid#io客户端的sid, socketio用此唯一标识客户端.

    #print('My sid =', CLIENT_VALUES['my_sid'])

    # "connect" and "disconnect" are 2 special events generated by socketIO upon socket creation
    # and destruction. "abort" is a custom event that we created upon server stopping.
    sio.on('connect', connect)
    sio.on('disconnect', disconnect)
    sio.on('abort', abort)


    ###
    sio.on('complete', complete)   # zhushi in 10.11
    ###    


    ############################################################################

    # Load the secret input "x"
    a = secrets.randbits(32)
    np.random.seed(a)
    CLIENT_VALUES['x'] = (np.random.normal(50, 20, NB_CLASSES))  

    ############# ROUND 0 ###############
    ### GENERATE AND SEND PUBLIC KEYS ###
    #####################################
    round0()

    ############### ROUND 1 ##################
    ###   RECEIVE PUBKEYS FROM EVERYONE,   ###
    ### GENERATE AND SEND ENCRYPTED SHARES ###
    ##########################################
    sio.on('ROUND_1', round1_handler)

    ########### ROUND 2 ##############
    ### MASK AND SEND INPUT VECTOR ###
    ##################################
    sio.on('ROUND_2', round2_handler)

    ################ ROUND 3 ##################
    ### SEND MASKS (AND POTENTIALLY SHARES) ###
    ###########################################
    sio.on('ROUND_3', round3_handler)


    ################ ROUND 4 ##################
    ###VERIFICATION THE CORRECTNESS BY IB&EG###
    ###########################################

    sio.on('ROUND_4', round4_handler)
