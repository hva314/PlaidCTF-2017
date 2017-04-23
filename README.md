# PlaidCTF-2017

## multicast - 175

Hastad's broadcast attack using Coppersmith method.
We have 1 message, linearly padding, decrypted by multiple public key (Ni, e=5)
According to Theorem 2 (Hastad): `If a large enough group of people is involved, the attacker can recover the plaintext Mi from all the ciphertext with similar methods`

```
ai = [] # store all a1, a2, a3, a4, a5
bi = [] # store b1, b2, b3, b4, b5
ci = [] # store c1, c2, c3, c4, c5
ni = [] # store n1, n2, n3, n4, n5
```

we need to find all coefficient Ti's sastifying that 
```python
Ti = 1 (mod Ni) and Ti = 0 (mod Nj) for all i!=j
```
by using Chinese Remainder Theorem
```python
T = [] 
T.append(crt([1,0,0,0,0],ni))
T.append(crt([0,1,0,0,0],ni))
T.append(crt([0,0,1,0,0],ni))
T.append(crt([0,0,0,1,0],ni))
T.append(crt([0,0,0,0,1],ni))
```
According to Hastad's, we have `g(x)= (Sigma)i*Ti*gi(x) that g(M) = 0 (mod (Pi)Ni)`<br>
By using coppersmith method, we can compute the root x[0] = M
Hastad stated that M exist among roots of Coppersmith method, in this case we only have 1 root

```python
N = ni[0]*ni[1]*ni[2]*ni[3]*ni[4]
P.<x> = PolynomialRing(Zmod(N))

# construct g(x)
g = 0
for i in range(len(ai)):
    g += (i+1)*T[i]*( (ai[i]*x + bi[i])^5 - ci[i])

# g(x) has to be monic polynomial in order to use coppersmith approach
g = g.monic()

# coppersmith method in Sage
M = g.small_roots()

# and we get the message
hex(int(M[0]))[2:-1].decode("hex")
'PCTF{L1ne4r_P4dd1ng_w0nt_s4ve_Y0u_fr0m_H4s7ad!}'
