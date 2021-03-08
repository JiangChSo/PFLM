#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from diffie_hellman import DHKE

from oblivious_transfer import OT_Sender, OT_Receiver

from AES_encryption import AESCipher

DHKE = DHKE(groupID=666)

# sk, pk = DHKE.generate_keys()
#
# print(sk)
# print('LENGTH:', len(str(sk)))
#
# print()
#
# shares = SecretSharer.split_secret(sk, 5, 6)
# # for s in shares:
# #     print('-', s)
# #     print('LENGTH:', len(str(s)))
# # print()
#
# secretTrue = SecretSharer.recover_secret(shares[0:5])
# print(secretTrue == sk)
#
# secretFalse = SecretSharer.recover_secret(shares[0:4]) # not enough
# print(secretFalse == sk)

sk1, pk1 = DHKE.generate_keys()
sk2, pk2 = DHKE.generate_keys()

shared_key = DHKE.agree(sk1, pk2)
shared_key2 = DHKE.agree(sk2, pk1)

assert shared_key == shared_key2


# TODO: Use KDF to generate AES key


sender = OT_Sender('Dentifrice', 'Laboratoire')
receiver = OT_Receiver(1)

A = sender.generate_A()
# print('A =', A)
B = receiver.generate_B(A)
# print('B =', B)
e0, e1 = sender.generate_e0_e1(B)
# print('e0 =', e0)
# print('e1 =', e1)
value = receiver.obtain_value(e0, e1)

print(value)

# AES_KEY = 'My_Key'
# system = AESCipher(AES_KEY)
# msg = 'Tu penses a quoi?' # ONLY ASCII characters --> 'à' will break padding
# c = system.encrypt(msg)
# print(c)
