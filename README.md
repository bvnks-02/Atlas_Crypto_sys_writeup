Atlas_Crypto_sys_writeup

In this repo you will find the writeup for the challenge Atlas Cryptosystem from CTF El Djazair.

Challenge Description

Atlas Crypto system is a key exchanege system developed by algerien cryto scientist can u crack it ?

Challenge Script

import random
from Crypto.Util.number import getPrime as get_prime

class AtlasCryptosystem:
    def __init__(self, p=None):
        self.p = get_prime(1024) if p is None else p
        u = [random.getrandbits(1024) for _ in range(1024)]
        self.private_key = sum(u)
        self.public_key = self.private_key % self.p
        self.shared_key = None

    def start_exchange(self):
        return (self.public_key, self.p)

    def exchange(self, y_other):
        S = self.private_key
        y_self = self.public_key
        self.shared_key = (y_self * y_other * y_other * S) % self.p

    def encrypt(self, m):
        return m * self.shared_key

    def decrypt(self, c):
        return c // self.shared_key

Data

p = 0xf9d4a2e8b0c7f3e1a5937d6b2c5a8f1e3d7b4a6c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5

y_A = 0x8a3d7b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5

y_B = 0x3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5

c = 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5

Solution

As u can see, to solve this traditionally by reversing the process won't work because there's not enough data to do that. We have 3 unknown variables: the private key, the shared secret, and the message. In a modular system, it's likely impossible to figure out a solution with this data alone.

To solve this, we need to think more simply.

As u notice, the ciphertext is generated like: C = m * shared_key (without modular transformation), which will help us reverse this operation without a problem if we had one of them.

The solution is to factorize the ciphertext to prime factors and then retrieve all possible factors of it, which is computationally possible and even easy because C isn't like RSA modulus (two-prime composite) and cannot be controlled through the process to make it hard to factor.

After we get all the factors, we try with each one of them if it is the message using the long_to_bytes() function.

This approach will give us the message since multiplying by the shared key is just a scaling operation.

Sample Script

from Crypto.Util.number import long_to_bytes
from sympy.ntheory import factorint

c = 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5

factors = factorint(c)
candidates = [1]

for prime, exp in factors.items():
    candidates = [x * (prime ** e) for x in candidates for e in range(exp + 1)]

for shared_key in candidates:
    if c % shared_key != 0:
        continue
    m = c // shared_key
    try:
        msg = long_to_bytes(m)
        if b'CTF' in msg or b'{' in msg:
            print(f"[*] Found: {msg.decode()}")
            break
    except:
        continue

🧠 The key idea: simple multiplication without mod means we can brute-force the shared key through factor trials.

🔎 Just check each factor of C, divide C by that factor, and see if it converts cleanly into a readable message.
