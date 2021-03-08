

'''
x1 = 1.1
x2 = 4.3

g = 2

p = 11

y1 = pow(g,x1)
y2 = pow(g,x2)

print(y1,y2)
print(y1*y2)
y = y1*y2%p
print(y)

y = pow(g,x1+x2)%p
print(y)
'''


from VElGamal import *

veg = VEG()

print(veg.get_params())

k_n1, Kn1 = veg.generate_keys()
print("k_n1, Kn1:",k_n1, Kn1)

#x_n1 = [1.1, 1.02, 2.36]
x_n1 = [1,2,3]
Cn1 = veg.enc(x_n1,k_n1)

print(Cn1)

k_n2, Kn2 = veg.generate_keys()
print("k_n2, Kn2:",k_n2, Kn2)

#x_n2 = [3.1, 0.52, 1.22]
x_n2 = [4,5,6]
Cn2 = veg.enc(x_n2,k_n2)

print(Cn2)


Kn_list = [Kn1,Kn2]
Cn_list = [Cn1, Cn2]
z_list = []
for i in range(len(x_n1)):
    z_list.append(x_n1[i]+x_n2[i])
print(z_list)

bool = veg.elverify(Kn_list,Cn_list, z_list)
print(bool)





'''
x1 = 1.101
x2 = 4.323

g = 2

p = 11

y1 = pow(g,x1)
y2 = pow(g,x2)

print(y1,y2)
print(y1*y2)
y = y1*y2%p
print(y)

y = pow(g,x1+x2)%p
print(y)
'''
