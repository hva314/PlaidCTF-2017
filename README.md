# PlaidCTF-2017

## Zipper - 50 

I have this alert when trying to unzip the file:
```
⮩ unzip zipper_50d3dc76dcdfa047178f5a1c19a52118.zip                                     
Archive:  zipper_50d3dc76dcdfa047178f5a1c19a52118.zip
warning:  filename too long--truncating.
:  bad extra field length (central)
```
From the alert, it sugests that the "file name" bytes and "extra length" bytes are not correct.<br>
Here is a useful document about zip file: <https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html><br>

File:
```
00000000: 504b 0304 1400 0200 0800 fc99 924a 3ea9  PK...........J>.
00000010: 2e53 4600 0000 f600 0000 2923 1c00 0000  .SF.......)#....
00000020: 0000 0000 0000 5554 0900 035b c8f6 585b  ......UT...[..X[
00000030: c8f6 5875 780b 0001 04e8 0300 0004 e803  ..Xux...........
00000040: 0000 5350 2004 b814 082b f128 adaa 4acc  ..SP ....+.(..J.
00000050: d051 a8cc 2f55 c848 2c4b 5548 4e2c 2829  .Q../U.H,KUHN,()
00000060: 2d4a 4d51 28c9 4855 48cb 494c b7e2 0a70  -JMQ(.HUH.IL...p
00000070: 0e71 ab4e 3328 4acd 2b36 4c2e 8eaf 4cac  .q.N3(J.+6L...L.
00000080: ac25 c326 ea28 0100 504b 0102 1e03 1400  .%.&.(..PK......
00000090: 0200 0800 fc99 924a 3ea9 2e53 4600 0000  .......J>..SF...
000000a0: f600 0000 2923 1800 0000 0000 0100 0000  ....)#..........
000000b0: b481 0000 0000 0000 0000 0000 0000 5554  ..............UT
000000c0: 0500 035b c8f6 5875 780b 0001 04e8 0300  ...[..Xux.......
000000d0: 0004 e803 0000 504b 0506 0000 0000 0100  ......PK........
000000e0: 0100 4e00 0000 8800 0000 0000            ..N.........
```
Pretty short file, I'm just gonna change it by hand.<br>
The `0800` replaced `2923`, 8 is the length of the filename. We know the length base on the fact that there is 8-blank bytes at the location of "extra length" bytes.<br>
The `666c 6167 2e74 7874` replaced `0000 0000 0000 0000`. You can name it whatever you want, I just make it `flag.txt` in this case. exactly 8 characters of length.<br>
Have 2 of those modifies both at the header and the end of the zip file.
And this is what we have.

```
00000000: 504b 0304 1400 0200 0800 fc99 924a 3ea9  PK...........J>.
00000010: 2e53 4600 0000 f600 0000 0800 1c00 666c  .SF...........fl
00000020: 6167 2e74 7874 5554 0900 035b c8f6 585b  ag.txtUT...[..X[
00000030: c8f6 5875 780b 0001 04e8 0300 0004 e803  ..Xux...........
00000040: 0000 5350 2004 b814 082b f128 adaa 4acc  ..SP ....+.(..J.
00000050: d051 a8cc 2f55 c848 2c4b 5548 4e2c 2829  .Q../U.H,KUHN,()
00000060: 2d4a 4d51 28c9 4855 48cb 494c b7e2 0a70  -JMQ(.HUH.IL...p
00000070: 0e71 ab4e 3328 4acd 2b36 4c2e 8eaf 4cac  .q.N3(J.+6L...L.
00000080: ac25 c326 ea28 0100 504b 0102 1e03 1400  .%.&.(..PK......
00000090: 0200 0800 fc99 924a 3ea9 2e53 4600 0000  .......J>..SF...
000000a0: f600 0000 0800 1800 0000 0000 0100 0000  ................
000000b0: b481 0000 0000 666c 6167 2e74 7874 5554  ......flag.txtUT
000000c0: 0500 035b c8f6 5875 780b 0001 04e8 0300  ...[..Xux.......
000000d0: 0004 e803 0000 504b 0506 0000 0000 0100  ......PK........
000000e0: 0100 4e00 0000 8800 0000 0000            ..N.........
```
And we can extract it.
```
Huzzah, you have captured the flag:
PCTF{f0rens1cs_yay} 
```
<hr>

## multicast - 175

Hastad's broadcast attack using Coppersmith method.
We have 1 message, linearly padding, decrypted by multiple public keys (Ni, e=5)
According to Theorem 2 (Hastad): `If a large enough group of people is involved, the attacker can recover the plaintext Mi from all the ciphertext with similar methods`

```
ai = [] # store all a1, a2, a3, a4, a5
bi = [] # store b1, b2, b3, b4, b5
ci = [] # store c1, c2, c3, c4, c5
ni = [] # store n1, n2, n3, n4, n5
```

we need to find all coefficient Ti's sastifying that `Ti = 1 (mod Ni) if i=j and Ti = 0 (mod Nj) for all i!=j` <br>
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
