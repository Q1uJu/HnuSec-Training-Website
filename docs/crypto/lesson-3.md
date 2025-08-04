# 对称密码

## 分组密码(块密码)

### Basis

```python
from os import urandom
from Crypto.Util.number import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

plaintext = b'I hope you can enjoy the cryptography!'
key = b'This is a key!!!'
iv = urandom(16)
print(iv)
# b'\x1f\xdb,Y\xca\x15U\xde\x99\xd2/G\xd7`\x81\xba'
plaintext_value = bytes_to_long(plaintext)
print(plaintext_value)
# 9310093868816787877666045616093516370642060605295364068354471587913057778851431178209622305
print(hex(plaintext_value))
# 0x4920686f706520796f752063616e20656e6a6f79207468652063727970746f67726170687921
print(hex(plaintext[0]))
# 0x49
for i in plaintext:
    print(hex(i)[2:], end="")
# 4920686f706520796f752063616e20656e6a6f79207468652063727970746f67726170687921
print("\n")
plaintext_padded = pad(plaintext,  16)
print(plaintext_padded)
# b'I hope you can enjoy the cryptography!\n\n\n\n\n\n\n\n\n\n'
print(unpad(plaintext_padded, 16))
# b'I hope you can enjoy the cryptography!'
# ECB
ecb = AES.new(key, AES.MODE_ECB)
ciphertext_ecb = ecb.encrypt(plaintext_padded)
print(ciphertext_ecb)
# b'\xa6\x8e{\xef\x07\x04\xc0c\xb7\xa06\n\x93\xde\xa4T\x85\xdbK\x81[\xaf& \xc8\xb8L\xd7\x12\x91pRd}bVF\xb7\x83\x8e\x9a\x9e\xe3\x05\x0f\x8c\xf8\x8b'
print(unpad(ecb.decrypt(ciphertext_ecb), 16))
# b'I hope you can enjoy the cryptography!'
ciphertext_ecb2 = ecb.encrypt(b'1' * 32)
print(ciphertext_ecb2)
# b"B'\x1a\r\x02h\xb4\xa7?\x96\xc7\xd2\xe0 \xd2\x9cB'\x1a\r\x02h\xb4\xa7?\x96\xc7\xd2\xe0 \xd2\x9c"

# CBC
cbc = AES.new(key, AES.MODE_CBC, iv)
ciphertext_cbc = cbc.encrypt(plaintext_padded)
print(ciphertext_cbc)
# b'\x19\x7fR\xfce\xd4E\xdb\xe7\x16\xcb\x96\xcbm\xc4\xac\xeb\xcd\x16\xbf\xfbd\x1e\xf5\xbd\x17\xeeM\xe3\xd0F4#\xf5\xb6/P&(\xbe\xb5<\x04\x83\r\xd6&\xf9'
# pycryptodome(以及大多数密码学库)的设计原则
cbc_decrypt = AES.new(key, AES.MODE_CBC, iv)
print(unpad(cbc_decrypt.decrypt(ciphertext_cbc), 16))
# b'I hope you can enjoy the cryptography!'
```

### DES

![image-20250725082556313](https://gitee.com/Q1uJu/picture_bed/raw/master/image-20250725082556313.png)

Cipher Function内就是扩展置换, S盒替换, P盒替换三步.

[DES论文](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf)

#### 弱密钥

在DES的计算中, 56bit的密钥最终会被处理为16个轮密钥, 每一个轮密钥用于16轮计算中的一轮, DES弱密钥会使这16个轮密钥完全一致, 故称为弱密钥.

四个弱密钥:

> \x01\x01\x01\x01\x01\x01\x01\x01
> \xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE
> \xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1
> \x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E

不考虑校验位的弱密钥:

> \x00\x00\x00\x00\x00\x00\x00\x00
> \xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF
> \xE1\xE1\xE1\xE1\xF0\xF0\xF0\xF0
> \x1E\x1E\x1E\x1E\x0F\x0F\x0F\x0F

PC1计算后弱密钥生成的轮密钥会变为全0, 全1或全部01交替. 当加密一次后看起来密文没什么问题的, 但是再加密一次就会得到明文.

https://aes.cryptohack.org/triple_des/

### AES

#### ECB

最简单的加密模式: **电子密码本**(Electronic codebook, ECB)模式. 此模式下要将明文分块, 然后用相同的加密方式和密钥进行加密, 未加其余混淆值. 所以如果加密同样的明文块会得到同样的密文块.

![image-20250724145332367](https://gitee.com/Q1uJu/picture_bed/raw/master/image-20250724145332367.png)

##### [DownUnderCTF 2025]ECB-A-TRON 9000

题源网站: https://beginner-ecb-a-tron-9000-1fc633e2ebf6.2025.ductf.net/

![image-20250724144750287](https://gitee.com/Q1uJu/picture_bed/raw/master/image-20250724144750287.png)

zydI4mywdNUekjgXe+ghRg

`exp.py`:

```python
# -*- coding: utf-8 -*-
"""
@version: python 3.12.4
@author: Q1uJu
@date: 2025/07/22
"""
import time
from tqdm import *
from base64 import *
from requests import *
from string import ascii_uppercase

url = "https://beginner-ecb-a-tron-9000-1fc633e2ebf6.2025.ductf.net/encrypt"

flag = ""
for i in tqdm(range(16)):
    format_str = "1" * (15 - i)
    format_data = b64encode(format_str.encode()).decode()
    format_json = {'data': format_data}
    format_res = post(url, json=format_json)
    format_ciphertext = b64decode(format_res.json()['ciphertext'])[:16]
    for j in ascii_uppercase:
        print(f"Try {j}...")
        brute_str = format_str + flag + j
        brute_data = b64encode(brute_str.encode()).decode()
        brute_json = {'data': brute_data}
        brute_res = post(url, json=brute_json)
        brute_ciphertext = b64decode(brute_res.json()['ciphertext'])[:16]
        if brute_ciphertext == format_ciphertext:
            flag += j
            break
    time.sleep(2)
print("DUCTF{" + flag + "}")
# DUCTF{DONTUSEECBPLEASE}
```

#### CBC

**密码分组链接**(Cipher-block chaining, CBC)模式. 在CBC模式中, 每个明文块先与前一个密文块进行异或后, 再进行ECB加密后得到密文分组. 对于第一块明文, 引入初始向量`iv`这个概念.

![image-20250724145558091](https://gitee.com/Q1uJu/picture_bed/raw/master/image-20250724145558091.png)

##### ez_cbc

**题目:**

```python
from Crypto.Util.number import *
import random
from secret import flag

IV = bytes_to_long(b'cbc!') 
K = random.randrange(1,1<<30)

assert flag[:7] == b'moectf{'
assert flag[-1:] == b'}'

block_length = 4
flag = flag + ((block_length - len(flag) % block_length) % block_length) * b'\x00'
plain_block = [flag[block_length * i: block_length * (i + 1)] for i in range(len(flag) // block_length)]

c = []
c0 = (IV ^ bytes_to_long(plain_block[0])) ^ K
c.append(c0)

for i in range(len(plain_block)-1):
    c.append(c[i] ^ bytes_to_long(plain_block[i+1]) ^ K)

print(c)

'''
[748044282, 2053864743, 734492413, 675117672, 1691099828, 1729574447, 1691102180, 657669994, 1741780405, 842228028, 1909206003, 1797919307]
'''
```

$$
c_0=IV\oplus p_0\oplus key\\
p\oplus k \oplus k=p\\
key=c_0\oplus p_0 \oplus IV\\
$$

$$
c_i=IV\oplus p_{i+1}\oplus key\\
p_1=IV\oplus p_{0} \oplus key
$$

`exp.py`:

```python
from Crypto.Util.number import *

c = [748044282, 2053864743, 734492413, 675117672, 1691099828, 1729574447, 1691102180, 657669994, 1741780405, 842228028, 1909206003, 1797919307]
iv = bytes_to_long(b'cbc!')
flag = b'moec'
m0 = bytes_to_long(flag)
# 计算 K
# C0 = IV ^ P0 ^ K  =>  K = IV ^ P0 ^ C0
K = m0 ^ c[0] ^ iv
assert c[0] == iv ^ m0 ^ K
for i in range(len(c) - 1):
    flag += long_to_bytes(c[i] ^ c[i + 1] ^ K)
end = flag.rindex(b'}')
print(flag[:end + 1].decode())
# moectf{es72b!a5-njad!@-#!@$sad-6bysgwy-1adsw8}
```

##### [安洵杯 2020]easyaes

**题目:**

```python
#!/usr/bin/python
from Crypto.Cipher import AES
import binascii
from Crypto.Util.number import bytes_to_long
from flag import flag
from key import key

iv = flag.strip(b'd0g3{').strip(b'}')

LENGTH = len(key)
assert LENGTH == 16

hint = os.urandom(4) * 8
print(bytes_to_long(hint)^bytes_to_long(key))

msg = b'Welcome to this competition, I hope you can have fun today!!!!!!'

def encrypto(message):
    aes = AES.new(key,AES.MODE_CBC,iv)
    return aes.encrypt(message)

print(binascii.hexlify(encrypto(msg))[-32:])

'''
56631233292325412205528754798133970783633216936302049893130220461139160682777
b'3c976c92aff4095a23e885b195077b66'
'''
```

`exp.py`:

```python
from Crypto.Cipher import AES
from Crypto.Util.number import *

xor_res = 56631233292325412205528754798133970783633216936302049893130220461139160682777
ciphertext = b'3c976c92aff4095a23e885b195077b66'
ciphertext = bytes.fromhex(ciphertext.decode())
msg = b'Welcome to this competition, I hope you can have fun today!!!!!!'
m = [msg[i:i + 16] for i in range(0, len(msg), 16)]
# print(long_to_bytes(xor_res))
# b'}4$d}4$d}4$d}4$d\x19\x04CW\x06CA\x08\x1e[I\x01\x04[Q\x19'
hint = b'}4$d' * 8
key = long_to_bytes(xor_res ^ bytes_to_long(hint))
# print(key)
# b'd0g3{welcomeyou}'
cipher = AES.new(key, AES.MODE_ECB)
for mi in m[::-1]:
    ciphertext = long_to_bytes(bytes_to_long(cipher.decrypt(ciphertext)) ^ bytes_to_long(mi))
    print(mi, ciphertext)
print("NSSCTF{" + ciphertext.decode() + "}")
# NSSCTF{aEs_1s_SO0o_e4sY}
```

#### CTR

![image-20250724150142909](https://gitee.com/Q1uJu/picture_bed/raw/master/image-20250724150142909.png)

##### 例题

**题目:**

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util import Counter
from hashlib import sha256
from secret import flag

import os


def padding(msg):
    return msg + os.urandom(16 - len(msg) % 16)


msg = b"where is the flag? Key in my Heart/Counter!!!!"
key = b"I w0nder how????"

assert len(msg) == 46
assert len(key) == 16

enc_key = os.urandom(16)
initial_value = bytes_to_long(enc_key)
hash = sha256(str(initial_value).encode()).hexdigest()

aes = AES.new(enc_key, AES.MODE_ECB)
enc_flag = aes.encrypt(padding(flag))

ctr = Counter.new(AES.block_size * 8, initial_value=initial_value)
aes = AES.new(key, counter=ctr, mode=AES.MODE_CTR)
enc = aes.encrypt(msg)

print("enc = {}".format(enc[-16:]))
print("enc_flag = {}".format(enc_flag))
print("hash = {}".format(hash))

'''
enc = b'\xbe\x9bd\xc6\xd4=\x8c\xe4\x95bi\xbc\xe01\x0e\xb8'
enc_flag = b'\xb2\x97\x83\x1dB\x13\x9b\xc2\x97\x9a\xa6+M\x19\xd74\xd2-\xc0\xb6\xba\xe8ZE\x0b:\x14\xed\xec!\xa1\x92\xdfZ\xb0\xbd\xb4M\xb1\x14\xea\xd8\xee\xbf\x83\x16g\xfa'
hash = efb07225b3f1993113e104757210261083c79de50f577b3f0564368ee7b25eeb
'''

```

`exp.py`:

```python
from Crypto.Util.number import *
from Crypto.Util.strxor import *
from Crypto.Cipher import AES
from hashlib import sha256
from tqdm import tqdm

enc = b'\xbe\x9bd\xc6\xd4=\x8c\xe4\x95bi\xbc\xe01\x0e\xb8'
enc_flag = b'\xb2\x97\x83\x1dB\x13\x9b\xc2\x97\x9a\xa6+M\x19\xd74\xd2-\xc0\xb6\xba\xe8ZE\x0b:\x14\xed\xec!\xa1\x92\xdfZ\xb0\xbd\xb4M\xb1\x14\xea\xd8\xee\xbf\x83\x16g\xfa'
hash = "efb07225b3f1993113e104757210261083c79de50f577b3f0564368ee7b25eeb"
msg = b"where is the flag? Key in my Heart/Counter!!!!"
key = b"I w0nder how????"

enc_counter_header = strxor(msg[-14:], enc[-14:])
for i in tqdm(range(2 ** 8, 2 ** 16)):
    enc_counter = enc_counter_header + long_to_bytes(i)
    cipher = AES.new(key, AES.MODE_ECB)
    counter = cipher.decrypt(enc_counter)
    initial_counter = bytes_to_long(counter) - 2
    if sha256(str(initial_counter).encode()).hexdigest() == hash:
        enc_key = long_to_bytes(initial_counter)
        decrypt = AES.new(enc_key, AES.MODE_ECB)
        flag = decrypt.decrypt(enc_flag)
        print(flag)
        break
# b'flag{9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d}@6\xf5R\xda\xa9'
```

## 流密码

### LCG

核心公式:
$$
state_0\equiv a*seed+b~(mod~p)\\
\vdots\\
state_n\equiv a*state_{n-1}+b~(mod~p)\\
$$

#### [LitCTF 2023]babyLCG

**题目:**

```python
from Crypto.Util.number import *
from secret import flag

m = bytes_to_long(flag)
bit_len = m.bit_length()
a = getPrime(bit_len)
b = getPrime(bit_len)
p = getPrime(bit_len+1)

seed = m
result = []
for i in range(10):
    seed = (a*seed+b)%p
    result.append(seed)
print(result)
"""
result = [...]
"""
```

给了所有的`result`, 也就是给了整个伪随机数序列.
$$
seed_n\equiv a*seed_{n-1}+b~(mod~p)\\
seed_{n-1}\equiv a*seed_{n-2}+b~(mod~p)\\
$$
由于没给`p`, 考虑想办法找出`p`为最大公因子的等式, 作差(差分法):
$$
diff_n=seed_n-seed_{n-1}\equiv a*(seed_{n-1}-seed_{n-2})~(mod~p)\\
diff_{n-1}=seed_{n-1}-seed_{n-2}\equiv a*(seed_{n-2}-seed_{n-3})~(mod~p)\\
diff_{n-2}=seed_{n-2}-seed_{n-3}\equiv a*(seed_{n-3}-seed_{n-4})~(mod~p)\\
\\
diff_3\equiv a*diff_2~(mod~p)\\
diff_2\equiv a*diff_1~(mod~p)\\
diff_3*diff_1-diff_2^2\equiv a^2*diff_1*diff_1-a*diff_1*a*diff_1\equiv 0~(mod~p)=k_1*p\\
$$
所以`p=gcd(diff[3]*diff[1]-diff[2]**2, diff[4]*diff[2]-diff[3]**2)`, 有了`p`以后, 消元:
$$
diff_{n}\equiv a*diff_{n-1}~(mod~p)\\
a\equiv diff_n*diff_{n-1}^{-1}~(mod~p)
$$
求出`a`回代到生成伪随机数的公式, 求出`b`:
$$
b\equiv seed_n-a*seed_{n-1}~(mod~p)
$$
`exp.py`:

```python
from gmpy2 import *
from Crypto.Util.number import *

result = [...]
diff = []
for i in range(len(result) - 1):
    diff.append(result[i + 1] - result[i])
p = gcd(diff[2] * diff[0] - diff[1] ** 2, diff[3] * diff[1] - diff[2] ** 2)
a = (diff[1]) * invert(diff[0], p) % p
b = (result[1] - result[0] * a) % p
m = (result[0] - b) * invert(a, p) % p
print(long_to_bytes(m).decode())
# LitCTF{31fcd7832029a87f6c9f760fcf297b2f}
```

## 其他加密算法

LFSR, MT19937涉及更底层的数学暂时也先不讲了(招新赛也没有出这两类题, 大家不用担心)

TEA, XXTEA, RC4, ChaCha20这些密码算法现在其实常见于REVERSE逆向题中, 所以就不讲了, 而且RC4和XXTEA我看REVERSE方向的师傅有讲应该, 就不抢课了(我自己也没很熟练啊哈哈哈哈)

## 课后作业

完成下面两个作业并交给我学习记录:

1. 在CRYPTOHACK里注册账号, 然后把HOW AES WORKS, SYMMETRIC STARTER, BLOCK CIPHERS 1部分完成, 应该都不算难, 有问题可以问我.
   - https://cryptohack.org/challenges/aes/
2. 在下面这些刷题网站里(不仅限于这些网站)刷题, DES和CTR的题目可能不多, 侧重ECB, CBC, LCG, 有余力的可以再做做其他对称算法的题, MT19937, LFSR等等.

## 推荐链接

### 刷题网站

- https://www.nssctf.cn/
- https://buuoj.cn/
- https://cryptohack.org/
- https://ctf.xidian.edu.cn/
- ...

### 博客

排序不分先后:

- https://mi1n9.github.io/
- https://shinichicun.top/
- https://lazzzaro.github.io/
- https://dexterjie.github.io/
- https://tangcuxiaojikuai.xyz/
- ...