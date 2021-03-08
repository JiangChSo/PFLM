from Crypto.Random.random import randint
from rfc_3526_groups import RFC_3526_GROUPS



class VEG:

    def __init__(self, groupID=14):
        self.g = 2
        self.q = 59568220895249410647994928463347713785037205991861431604737338991513566636345206084454215193331882242609500824232481490395886189078704706716593208952219165528309722404949905167098665737422779305882131040805818049290050769589377000953270794255067991822581282854963715000139264823136311377905592656205731271861
        self.y = 59568220895249410647994928463347713785037205991861431604737338991513566636345206084454215193331882242609500824232481490395886189078704706716593208952219165528309722404949905167098665737422779305882131040805818049290050769589377000953270794255067991822581282854963715000139264823136311377905592656205731270000
        #secret key y is given straightedly q 1024bit y 1024bit
    def get_params(self):
        return self.g, self.q ,self.y

    def generate_keys(self):
        k_n = randint(1, self.q - 1)
        Kn = pow(self.g, k_n, self.q)
        return k_n, Kn

    def enc(self, x_n, k_n):
        Cn=[]
        for i in range(len(x_n)):
            t = pow(self.g, x_n[i] + k_n*self.y,self.q)
            Cn.append(t)
        return Cn

    def elverify(self, Kn_list, Cn_list, z_list):
        bool = []
        yni = -self.y % (self.q -1) #10.12 right
        client_n = len(Cn_list)
        #print(client_n)
        x_n_n = len(Cn_list[0])
        for i in range(x_n_n):
            K = 1
            C = 1
            for j in range(client_n):
                K = K * Kn_list[j]%self.q
                C = C * Cn_list[j][i]%self.q
            
            zprime = (C * pow(K, yni, self.q))%self.q
            
            temp = []
            temp.append(pow(self.g,z_list[i],self.q))
            for j in range(client_n):
                j = j+1
                temp.append(pow(self.g, z_list[i] - j, self.q))
                temp.append(pow(self.g, z_list[i] + j, self.q))
            '''
            gz = pow(self.g,z_list[i],self.q)
            gz1 = pow(self.g,z_list[i]+1,self.q)
            gz2 = pow(self.g,z_list[i]+2,self.q)
            gz_1 = pow(self.g,z_list[i]-1,self.q)
            gz_2 = pow(self.g,z_list[i]-2,self.q)
            temp = [gz_2, gz_1, gz, gz1, gz2]
            print("zprime",zprime)
            print(gz)
            print(gz1)
            print(gz2)
            print(gz_1)
            print(gz_2)
            '''
            if zprime not in temp:
                return False    
        return True
    
    
        
