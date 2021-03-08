from pypbc import *

#双线性对的参数
stored_params = """type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1
"""
class IBAS:
    '''
    Setup
    '''
    def __init__(self):
        try:
            #q_1 = get_random_prime(80)
            q_1 = 694618736102223678932341#80bit
            #print(q_1)
            q_2 = 694618736102223678932341#80bit
            self.params = Parameters( n = q_1 * q_2)
            self.pairing = Pairing(self.params)
            self.s = Element.from_hash( self.pairing, Zr, "privatekey")
            self.P = Element.from_hash( self.pairing, G2,"generator")
            self.Q = Element(self.pairing, G2, value=self.P**self.s)

        except Exception:
            fail("Could not instantiate")
    '''
    Private key generation
    '''
    def PKG(self, Un):
        P_n0 = Element.from_hash( self.pairing, G2, "0" + Un)
        P_n1 = Element.from_hash( self.pairing, G2, "1" + Un)
        #print("0"+Un)
        #print("1"+Un)
        #print(P_n0)
        #print(P_n1)
        s = self.s
        sP_n0 = Element( self.pairing, G2, value = P_n0 ** s )
        sP_n1 = Element( self.pairing, G2, value = P_n1 ** s )
        #print("sp_n0:",sP_n0)
        #print("sp_n1:",sP_n1)
        return P_n0,P_n1,sP_n0,sP_n1
    '''
    Individual Signing
    '''
    def InSign(self, w, Mn, Un, sP_n0, sP_n1):
        P_w = Element.from_hash( self.pairing, G2, w)
        c_n = Element.from_hash( self.pairing, Zr, Un + Mn + w)
        r_n = Element.random( self.pairing, Zr)
        S_n = Element( self.pairing, G2, value = P_w ** r_n + sP_n0 + sP_n1 ** c_n)
        T_n = Element( self.pairing, G2, value = self.P ** r_n )
        sigma_n = [w, S_n, T_n]
        return sigma_n
    '''
    Aggregation
    '''
    def Aggre(self, w, S_n_list, T_n_list):
        S_w = Element.zero( self.pairing, G2 )
        T_w = Element.zero( self.pairing, G2 )
        for i in range(len(S_n_list)):
            S_w = Element( self.pairing, G2, value = S_w + S_n_list[i])
            T_w = Element( self.pairing, G2, value = T_w + T_n_list[i])
        return w,S_w,T_w
    '''
    Verification
        allUn:list
        allMn:list
    '''
    def Verify(self, allUn, w, S_w, T_w, allMn):
        P_n0_list = []
        P_n1_list = []
        c_n_list = []
        n_client = len(allUn)
        for i in range(n_client):
            P_n0 = Element.from_hash( self.pairing, G2, "0" + str(allUn[i]))
            P_n0_list.append(P_n0)
            P_n1 = Element.from_hash( self.pairing, G2, "1" + str(allUn[i]))
            P_n1_list.append(P_n1)
            c_n = Element.from_hash( self.pairing, Zr, allUn[i] + allMn[i] + w)
            c_n_list.append(c_n)
        P_w = Element.from_hash( self.pairing, G2, w)
        left = self.pairing.apply(S_w,self.P)
        #print("left:",left)
        right1 = self.pairing.apply(T_w,P_w)
        right21 = Element.zero( self.pairing, G2 )
        for i in range(n_client):
            right21 = Element( self.pairing, G2, value = right21 + P_n0_list[i]+Element( self.pairing, G2, value = P_n1_list[i] ** c_n_list[i] ))

        right2 = self.pairing.apply(self.Q, right21)
        right =  right1*right2
        #print("right:",right)
        return left==right
                    
        
    	
    	
    	
