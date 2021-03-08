
from AggregateSignatures import IBAS

from pypbc import *
import pypbc

'''test first
#Setup
ibas = IBAS()
s = ibas.s
P = ibas.P
Q = ibas.Q
#print(ibas.params)
#print(ibas.s)
#print(ibas.P)
#print(ibas.Q)
pairing = ibas.pairing
P_n0_list = []
P_n1_list = []
S_n_list = []
T_n_list = []
c_n_list = []
client_n = 2
for i in range(client_n):
    #Private key generation
    P_n0 = Element.from_hash( pairing, G2, "Un"+str(i)+"0")
    P_n0_list.append(P_n0)
    P_n1 = Element.from_hash( pairing, G2, "Un"+str(i)+"1")
    P_n1_list.append(P_n1)
    sP_n0 = Element( pairing, G2, value = P_n0 ** s )
    sP_n1 = Element( pairing, G2, value = P_n1 ** s )
    #Individual Signing
    P_w = Element.from_hash( pairing, G2, "w")
    c_n = Element.from_hash( pairing, Zr, "Mn"+"Un"+str(i)+"w")
    c_n_list.append(c_n)
    r_n = Element.random( pairing, Zr)
    S_n = Element( pairing, G2, value = P_w ** r_n + sP_n0 + sP_n1 ** c_n)
    S_n_list.append(S_n)
    #print(S_n)
    T_n = Element( pairing, G2, value = P ** r_n )
    T_n_list.append(T_n)
    #print(T_n)
    sigma_n = ['w', S_n, T_n]
    print(sigma_n)
    #print("sP_n0 = %s;sP_n1 = %s",sP_n0,sP_n1)
#Aggregation
S_w = Element.zero(pairing, G2)
T_w = Element.zero(pairing, G2)
for i in range(client_n):
    S_w = Element( pairing, G2, value = S_w + S_n_list[i])
    T_w = Element( pairing, G2, value = T_w + T_n_list[i])

#rint(S_w)
#rint(T_w)


#Verification

left = pairing.apply(S_w,P)
print(left)
right1 = pairing.apply(T_w,P_w)
right21 = Element.zero( pairing, G2 )
for i in range(client_n):
    right21 = Element( pairing, G2, value = right21 + P_n0_list[i]+Element( pairing, G2, value = P_n1_list[i] ** c_n_list[i] ))
print(right21)

right2 = pairing.apply(Q, right21)
right =  right1*right2
print(right)
print(left==right)
'''
#test onece object
ibas = IBAS()
pairing = ibas.pairing

Un0="Un0"
a,b,sP_n01,sP_n11 = ibas.PKG(Un0)
#print("publickey:",sP_n01,sP_n11)
w = "w"
Mn="Mn"
sigma0 = ibas.InSign(w,Mn,Un0,sP_n01,sP_n11)
print("sigma0",sigma0)

#the second user
Un1="Un1"
a,b,sP_n02,sP_n12 = ibas.PKG(Un1)
#print("publickey:",sP_n02,sP_n12)
sigma1 = ibas.InSign(w,Mn,Un1,sP_n02,sP_n12)
print("sigma1",sigma1)
#
S_n_list = [sigma0[1],sigma1[1]]
T_n_list = [sigma0[2],sigma1[2]]
w,S_w,T_w = ibas.Aggre(w,S_n_list,T_n_list)
print("aggreresult:",w,S_w,T_w)

#
allUn = [Un0, Un1]
allMn = [Mn, Mn]
correctness = ibas.Verify(allUn,w,S_w,T_w,allMn)
print("the result of verification: ",correctness)


print(a)
print(type(a))
stra = str(a)
print(stra)
print(type(stra))

cc = Element(pairing,G2,value=stra)

print(cc)
print(type(cc))

c_n = Element.from_hash( pairing, Zr,"1223444")
print("c_n",c_n)
print(type(c_n))
#strc_n = str(c_n)
#conc_n = Element(pairing,Zr,value=strc_n)

#print("conc_n",conc_n)

#print("**************8")
#print(type(conc_n))

q_1 = get_random_prime(80)
print(q_1)