# Blockchain Technology Cheatsheet

Welcome to the Alchemy University's Ethereum Developer Bootcamp! This cheatsheet summarizes essential concepts in blockchain technology, focusing on Ethereum, smart contracts, and cryptographic primitives.

---

## 📚 Blockchains

### 🎯 Purpose of a Blockchain

- To create a **network of computers** that agree on a **common state of data**.
- Participation should be open to **any person or organization**.
- No single entity should be able to control the process.
- This process of agreement is called **consensus**.

---

## 💸 Cryptocurrency Use-Case

### Why Blockchain is Needed

A naive digital currency without blockchain relies on a **centralized bookkeeper** and raises issues:

1. Trust in the bookkeeper (resistance to cheating/bribery).
2. Availability and up-to-date balances.
3. Scalability with increasing participants.

Blockchain solves **problem #1 — trust** — using **decentralization and cryptography**.

### 🔍 The Breakthrough

- In 2008, **Satoshi Nakamoto** proposed Bitcoin.
- Bitcoin described a **peer-to-peer value exchange system**.
- The system used **cryptography and game theory** to incentivize honest behavior.
- Data was stored in a **chain of cryptographically-linked blocks**, hence the term **blockchain**.

---

## 🧠 Smart Contract Blockchains

Smart contracts allow **code to run on a decentralized network**, making them:

- **Censorship-resistant**
- **Publicly accessible**
- **Transparent and verifiable**

### Example: Solidity Smart Contract

```solidity
// this data structure will keep track of which address has a balance
mapping(address => uint) balances;

function transfer(address to, uint amount) external {
  // subtract the amount from the sender's balance
  balances[msg.sender] -= amount;

  // add the amount to the recipient's balance
  balances[to] += amount;
}
```

- This is a basic ERC20 `transfer()` function.
- **Nothing special** about the function until it is **deployed to a blockchain**.
- Once deployed, its execution is **enforced by all nodes in the network**.

---

## 🔐 Cryptographic Hash Functions

### What is a Hash Function?

A **hash function** takes an input of any size and returns a **fixed-size output**.

| Input              | Input Size    | Output (Hash) | Output Size |
|--------------------|---------------|---------------|-------------|
| `52`               | 8 bytes       | `0x41cf...`   | 32 bytes    |
| `"happy times"`    | 22 bytes      | `0xd6bf...`   | 32 bytes    |
| `monalisa.jpg`     | 875000 bytes  | `0x7cde...`   | 32 bytes    |
| `worldseries.mp4`  | 1.6e+10 bytes | `0x9c0e...`   | 32 bytes    |

### 🔒 Cryptographic Hash Function Properties

1. **Deterministic**: Same input → same output
2. **Pseudorandom**: Outputs appear random and unpredictable
3. **One-way**: Infeasible to reverse-engineer the input
4. **Fast to Compute**: Efficient computation
5. **Collision-resistant**: Very unlikely two inputs produce same output

> Challenge: Try using a [SHA-256 tool](https://emn178.github.io/online-tools/sha256.html) and test these properties!

### 🧠 Why Hashing Matters for Blockchains

- **Save space**: Store hash instead of large inputs.
- **Enable validation**: Confirm data without storing all of it.
- **Foundation for consensus**: Core to Proof of Work systems.

---

## 🧩 Summary

- **Blockchain**: Decentralized ledger for trustless consensus.
- **Cryptocurrency**: First major use-case enabled by blockchain.
- **Smart Contracts**: Decentralized logic enforcing financial and programmatic rules.
- **Cryptographic Hash Functions**: Vital primitive for security, storage, and consensus.

---

# Public Key Cryptography Cheatsheet

---

## 🔐 Cryptography Historically

- Until the 1970s, cryptography focused on **encrypting messages** to keep them secret.
- Messages were encrypted by applying simple functions, e.g., shifting letters ("abc" → "bcd").
- Early encryption was **easy to break** once the secret method was known.
- Introduction of **secret keys** allowed two parties to agree on a key before communication.
- This is called **symmetric-key cryptography**: both sides share the same secret key.
- Cryptography evolved with more complex methods over time.

---

## 🖥️ Personal Computing and New Challenges

- Personal computing raised the problem: How to communicate **securely without prior key exchange**?
- Meeting in person to exchange keys was impractical.
- In 1976, **Whitfield Diffie** proposed the idea of a **public key**.
- Many initially rejected this because keys were meant to be private.

---

## 💡 Thought Experiment: Public and Private Keys

- There exists a **key pair**: a **private key** and a **public key**.
- Each key can decrypt messages encrypted by the other.
- Bob publishes his **public key** widely but keeps his **private key** secret.

### Digital Signatures (Proof of Origin)

- Bob **encrypts a message with his private key**.
- Anyone can decrypt it with Bob's public key.
- Only Bob could have created the message — **this forms a digital signature**.

### Confidential Messages

- Anyone can encrypt a message using Bob's **public key**.
- Only Bob can decrypt it with his **private key**.
- Enables **secure communication without prior key exchange**.

---

## 🔄 Asymmetric Encryption

- Public key cryptography is **asymmetric**:
  - One key (public) encrypts.
  - The other key (private) decrypts.
- Only the owner has access to the private key.

---

## ⚙️ Popular Algorithms: RSA and ECDSA

### RSA (Rivest–Shamir–Adleman)

- Based on the difficulty of **factoring large products of two primes**.
- Easy to multiply two primes, but hard to factor the product.
- Security depends on computational hardness (relates to **P vs NP problem**).
- Widely studied and used in many cryptographic systems.

### ECDSA (Elliptic Curve Digital Signature Algorithm)

- Uses **elliptic curves** for cryptography.
- Provides the same security with **smaller key sizes** compared to RSA.
- Used in Bitcoin and many cryptocurrencies (e.g., secp256k1 curve).
- Popular due to efficiency and strong security.

---

## 📚 Summary

- Cryptography evolved from simple secret-key methods to **asymmetric public-key systems**.
- Public key cryptography solves the problem of **secure communication without prior key exchange**.
- Digital signatures provide **proof of message origin and integrity**.
- RSA and ECDSA are two main algorithms powering modern secure communications and blockchain technology.

---

## References

- [RFC 6979 - Deterministic ECDSA](https://datatracker.ietf.org/doc/html/rfc6979)
- [SECG SEC 1 & SEC 2 Standards](https://www.secg.org/)
- [RFC 5639 - Brainpool Curves](https://datatracker.ietf.org/doc/html/rfc5639)



# Supplemental Resources on Digital Signatures

Below you'll find many supplemental resources on digital signatures!

Be sure to read/watch these resources as they will help deepen your understanding of these algorithms.

---

## ECDSA

- **[Cloudflare on ECDSA](https://www.cloudflare.com/learning/ssl/what-is-ecdsa/)**  
  A great article on how ECDSA is used on the web. If you've ever thought about how HTTPS works, this is your chance to dig in further!

- **[Wikipedia - ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)**  
  Naturally very math-heavy, but contains useful insights even for those not strong in math.

- **[Simplified ECDSA Math Explanation](https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages)**  
  A clearer and more accessible breakdown of the mathematics behind ECDSA.

---

## Bitcoin

- **[secp256k1 Curve Parameters](https://en.bitcoin.it/wiki/Secp256k1)**  
  Bitcoin uses secp256k1. Its parameters are thought to be less random, making it supposedly less likely to contain hidden backdoors.

- **[Bitcoin Address Derivation Diagram](https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses)**  
  Useful for understanding how Bitcoin derives addresses from public keys. The diagram at the bottom is especially helpful.

- **[Technical Detail on Address Derivation and Checksums](https://learnmeabitcoin.com/technical/address)**  
  Explains how Bitcoin includes checksums in addresses.

- **[Base58 Encoding in Bitcoin](https://en.bitcoin.it/wiki/Base58Check_encoding)**  
  Bitcoin chose Base58 to remove commonly mistaken characters like zero `0` and uppercase `O`.

---

## Diffie-Hellman Key Exchange

- **[TLS and Hybrid Cryptosystems](https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/)**  
  Diffie-Hellman is crucial to the TLS handshake, using asymmetric cryptography for the exchange and symmetric encryption for actual communication.

- **[Colorful Explanation of DH Key Exchange](https://www.khanacademy.org/computing/computer-science/cryptography/modern-crypt/v/diffie-hellman-key-exchange-part-1)**  
  An accessible and engaging introduction.

- **[Mathematical Explanation of DH](https://crypto.stackexchange.com/questions/5577/diffie-hellman-key-exchange-intuition)**  
  A more in-depth look at the math behind the protocol.

- **[Video on Elliptic Curves](https://www.youtube.com/watch?v=NF1pwjL9-DE)**  
  Great visual follow-up to understand how elliptic curves work.

---

## RSA

- **[Wikipedia - RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))**  
  A solid technical overview of the RSA algorithm.

- **[The Cryptobook - RSA Explained](https://cryptobook.nakov.com/asymmetric-key-ciphers/rsa-encryption-decryption)**  
  A plain English explanation of RSA, including the math.

- **[WooTube RSA Videos - Part 1](https://www.youtube.com/watch?v=wXB-V_Keiu8) & [Part 2](https://www.youtube.com/watch?v=gs3MKXe4VM0)**  
  Two excellent educational videos on the mathematics of RSA by Eddie Woo.

- **[Alleged RSA Backdoor](https://arstechnica.com/information-technology/2013/09/nsa-paid-security-firm-10-million-to-implement-backdoored-crypto/)**  
  Discussion of possible historical vulnerabilities or planted backdoors in RSA.

---

# ECDSA: Elliptic Curve Digital Signature Algorithm Cheatsheet

## Overview

ECDSA (Elliptic Curve Digital Signature Algorithm) is a cryptographic signature scheme that uses elliptic curve cryptography (ECC) to provide secure and efficient digital signatures.

- Based on the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**
- Uses **elliptic curves over finite fields**
- Provides **smaller key sizes** and **faster computations** than RSA for equivalent security

---

## Key Concepts

- **Elliptic Curve (EC)**: Defined by an equation in Weierstrass form over a finite field
- **Generator Point (G)**: A predefined EC point used for scalar multiplication
- **Order (n)**: The number of points in the subgroup generated by G
- **Private Key (privKey)**: A random integer ∈ [1, n - 1]
- **Public Key (pubKey)**: EC point `privKey * G`

---

## Example Curve: secp256k1

- Used in Bitcoin and Ethereum
- 256-bit security level

**Parameters:**
```
Order n:
115792089237316195423570985008687907852837564279074904382605163141518161494337

Generator G:
x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
```

---

## Key Generation

1. Generate a random `privKey` in `[1, n - 1]`
2. Compute `pubKey = privKey * G`

**Public key compression:**
- Store only x-coordinate + 1-bit parity
- ~33 bytes for secp256k1

---

## ECDSA Signing

### Input
- Message `msg`
- Private key `privKey`

### Output
- Signature `{r, s}`

### Steps
1. Compute hash:  
   ```h = hash(msg)```

2. Generate random `k ∈ [1, n - 1]`  
   - Use deterministic `k` from RFC 6979 if needed

3. Compute point:  
   ```R = k * G```  
   ```r = R.x mod n```

4. Compute signature proof:  
   ```
   s = k⁻¹ * (h + r * privKey) mod n
   ```

5. Output signature:  
   ```{r, s}```

---

## ECDSA Verification

### Input
- Message `msg`
- Signature `{r, s}`
- Public key `pubKey`

### Output
- Boolean: `true` (valid) or `false` (invalid)

### Steps
1. Compute hash:  
   ```h = hash(msg)```

2. Compute inverse:  
   ```s1 = s⁻¹ mod n```

3. Recover point:  
   ```
   R' = (h * s1) * G + (r * s1) * pubKey
   ```

4. Get x-coordinate:  
   ```r' = R'.x mod n```

5. Validate:  
   ```r' == r```

---

## How the Math Works

### Signature Equation
```
s = k⁻¹ * (h + r * privKey) mod n
```

### Verification Recovers:
```
R' = (h + r * privKey) * s⁻¹ * G
   = k * G
```

### Valid if:
```
R'.x == r
```

---

## Signature Size

| Curve       | Key Size | Signature Size |
|-------------|----------|----------------|
| secp256k1   | 256-bit  | 64 bytes       |
| secp521r1   | 521-bit  | 132 bytes      |

---

## Public Key Recovery

ECDSA allows public key recovery from:
- Signature `{r, s}`
- Message `msg`

### Extended Signature
- Format: `{r, s, v}` (with recovery ID `v`)
- Used in Ethereum and other blockchains

### Use Case
- Saves bandwidth and storage by not transmitting the public key separately

---

## Summary

| Component     | Description                                   |
|---------------|-----------------------------------------------|
| `privKey`     | Random integer ∈ `[1, n - 1]`                  |
| `pubKey`      | EC point: `privKey * G`                        |
| `r`           | x-coordinate of `R = k * G`                    |
| `s`           | Signature proof using `privKey` and `msg hash`|
| Signature     | `{r, s}` or `{r, s, v}`                        |
| Curve Example | secp256k1                                      |

---


# Diffie-Hellman Key Exchange (DHKE) Cheatsheet

The Diffie-Hellman Key Exchange (DHKE) is a method for securely exchanging cryptographic keys over a public channel. It enables two parties to jointly establish a shared secret used for encrypted communication.

---

## 🔑 Key Concepts

- **Asymmetric Key Exchange**: Uses public and private keys.
- **Symmetric Key Usage**: Resulting shared secret is used with symmetric encryption.
- **Security Based On**: Discrete logarithm problem (hard to reverse).

---

## 📚 Terminology

- `p`: A large prime number (public).
- `g`: A primitive root modulo `p` (public).
- `a`: Alice’s private key (secret).
- `b`: Bob’s private key (secret).
- `A`: Alice’s public key = `g^a mod p`.
- `B`: Bob’s public key = `g^b mod p`.
- `s`: Shared secret = `B^a mod p = A^b mod p`.

---

## 🔐 Step-by-Step Process

1. **Public Setup**  
   Both parties agree on a large prime `p` and a generator `g`.

2. **Private Key Generation**  
   Each party picks a private key:
   - Alice: chooses `a`
   - Bob: chooses `b`

3. **Public Key Computation**  
   Each party computes and shares their public key:
   - Alice: `A = g^a mod p`
   - Bob: `B = g^b mod p`

4. **Shared Secret Derivation**  
   Each computes the shared secret:
   - Alice: `s = B^a mod p`
   - Bob: `s = A^b mod p`

---

## 📄 Example (with small numbers)

```
p = 23
g = 5

Alice:
  a = 6
  A = 5^6 mod 23 = 8

Bob:
  b = 15
  B = 5^15 mod 23 = 2

Exchange:
  Alice sends A = 8
  Bob sends B = 2

Shared Secret:
  Alice: s = 2^6 mod 23 = 18
  Bob: s = 8^15 mod 23 = 18
```

Both compute the same shared secret: `s = 18`

---

## 🧠 Security

- **Depends On**: Difficulty of computing discrete logarithms in a finite field.
- **Eavesdropper Sees**: `p`, `g`, `A`, `B` but cannot compute the shared secret without solving the discrete log problem.

---

## 🔁 Variants

- **Elliptic Curve Diffie-Hellman (ECDH)**  
  Uses elliptic curves for improved performance and smaller keys.

- **Ephemeral Diffie-Hellman (DHE)**  
  Uses fresh key pairs per session to enable perfect forward secrecy.

---

## 🧪 Python Example

```python
import random

def diffie_hellman(p, g):
    a = random.randint(1, p - 2)
    b = random.randint(1, p - 2)

    A = pow(g, a, p)
    B = pow(g, b, p)

    s_A = pow(B, a, p)
    s_B = pow(A, b, p)

    assert s_A == s_B
    return s_A

shared_secret = diffie_hellman(23, 5)
print("Shared Secret:", shared_secret)
```

---

## 🛡️ Applications

- HTTPS (TLS)
- VPNs
- Messaging apps (e.g. Signal)
- Secure file sharing

---

## 📎 Resources

- [Wikipedia: Diffie–Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [Khan Academy Video](https://www.khanacademy.org/computing/computer-science/cryptography/modern-crypt/v/diffie-hellman-key-exchange-part-1)
- [RFC 2631](https://datatracker.ietf.org/doc/html/rfc2631)

---


# RSA Cryptosystem Cheatsheet

The RSA cryptosystem is an asymmetric encryption algorithm based on the mathematical difficulty of factoring large integers. It is widely used for secure data transmission.

---

## 🔐 Key Concepts

- **Asymmetric encryption**: Uses a public key to encrypt and a private key to decrypt.
- **Based on**: The difficulty of factoring the product of two large prime numbers.
- **Applications**: Secure communication, digital signatures, key exchange.

---

## 📚 Terminology

- `p`, `q`: Two large distinct prime numbers.
- `n`: The modulus, `n = p * q`.
- `φ(n)`: Euler's totient function, `φ(n) = (p-1)(q-1)`.
- `e`: Public exponent such that `1 < e < φ(n)` and `gcd(e, φ(n)) = 1`.
- `d`: Private exponent, `d ≡ e⁻¹ mod φ(n)`.
- `m`: Plaintext message (as a number).
- `c`: Ciphertext message.

---

## 🔧 Key Generation

1. Choose two large prime numbers: `p` and `q`.
2. Compute `n = p * q`.
3. Compute `φ(n) = (p - 1)(q - 1)`.
4. Choose public exponent `e` such that `gcd(e, φ(n)) = 1`.
5. Compute private exponent `d` as the modular inverse of `e` modulo `φ(n)`.

Public Key: `(n, e)`  
Private Key: `(n, d)`

---

## 🔒 Encryption & Decryption

- **Encryption**  
  To encrypt a message `m` using the public key `(n, e)`:
  ```
  c = m^e mod n
  ```

- **Decryption**  
  To decrypt a ciphertext `c` using the private key `(n, d)`:
  ```
  m = c^d mod n
  ```

---

## 📄 Example (with small numbers)

```
p = 61
q = 53
n = p * q = 3233
φ(n) = (p-1)*(q-1) = 3120
e = 17
d = 2753 (because 17 * 2753 ≡ 1 mod 3120)

Public Key: (3233, 17)
Private Key: (3233, 2753)

Message: m = 65
Encryption: c = 65^17 mod 3233 = 2790
Decryption: m = 2790^2753 mod 3233 = 65
```

---

## 🧪 Python Example

```python
from Crypto.Util.number import getPrime, inverse
import random

def generate_rsa_keys(bits=512):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)
    return (n, e), (n, d)

def encrypt(m, pubkey):
    n, e = pubkey
    return pow(m, e, n)

def decrypt(c, privkey):
    n, d = privkey
    return pow(c, d, n)

pub, priv = generate_rsa_keys()
message = 42
cipher = encrypt(message, pub)
plain = decrypt(cipher, priv)
print("Original:", message)
print("Encrypted:", cipher)
print("Decrypted:", plain)
```

---

## 🛡️ Security

- **Security relies on**: Difficulty of factoring large integers.
- **Key size**: Typically 2048 or 3072 bits.
- **Vulnerabilities**:
  - Poor random number generation
  - Small `e` without padding (e.g., textbook RSA)
  - Timing and side-channel attacks

---

## 📎 Use Cases

- SSL/TLS (HTTPS)
- PGP/GPG
- Digital signatures
- Secure key exchange

---

## 🧠 Best Practices

- Use padding schemes like OAEP or PKCS#1 v1.5.
- Avoid using RSA to encrypt large messages directly.
- Use hybrid encryption (RSA + AES).
- Rotate keys periodically.

---

## 📘 Resources

- [Wikipedia: RSA (cryptosystem)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [CryptoBook by Boneh & Shoup](https://cryptobook.us/)
- [WooTube RSA Math Part 1](https://www.youtube.com/watch?v=wXB-V_Keiu8)
- [WooTube RSA Math Part 2](https://www.youtube.com/watch?v=pu4cLHSXoLY)

---


# Proof of Work & Mining

Blockchain networks, like Ethereum, are distributed and decentralized databases consisting of many nodes (computers running the protocol).

---

## 🤔 The Coordination Problem

In decentralized systems, several key questions arise:

- How do all nodes agree on the current and future state of accounts and contract interactions?
- Who gets to add new transactions to the blockchain?
- How can we ensure added blocks are valid?
- How is all this coordinated without a central authority?

👉 The answer: **Consensus Mechanisms**

---

## 🧠 Consensus Mechanisms

**Consensus** means achieving general agreement. In blockchain, consensus refers to 51% or more nodes agreeing on the network's global state.

Consensus mechanisms are sets of rules that decentralized blockchains follow to remain in sync and validate transactions. They're interchangeable, and different networks use different mechanisms (e.g., Proof of Stake, Proof of Work).

### 🔑 Rules in Proof-of-Work (PoW)

- ❌ No double spending.
- 🔗 The **longest chain (by work)** is the valid chain — a principle known as **Nakamoto Consensus**.

---

## ⛏️ Proof of Work (PoW)

Proof-of-Work is a consensus mechanism that:

- Ensures agreement on balances and transaction order.
- Prevents double spending.
- Provides **security through computational effort**.

### How it works:

Miners (special nodes) try to create new blocks by solving a computational puzzle. The "proof" that work was done is a valid hash output, which is hard to find but easy to verify.

---

## 🏗️ What is Mining?

**Mining** = The process of producing a valid block to add to the chain.

Although the term was inspired by gold mining (due to its resource-intensive nature), it really just means:

> Competing to solve a cryptographic puzzle to secure the network and earn rewards.

---

## ⚙️ How PoW Mining Works

To mine a block:

1. Gather:
   - Previous block header
   - Pending transactions (mempool)
2. Append a `nonce` (starts at 0)
3. Hash the combination (header + transactions + nonce)
4. Compare hash against the **target difficulty**
   - If `hash < target`, block is valid
   - If not, increment nonce and repeat

💡 This process is repeated millions of times per second by miners worldwide.

---

## 🔢 Target Difficulty

The **target difficulty** defines how hard it is to find a valid hash.

Example (Bitcoin):  
A valid hash might look like:
```
000000000000000000043f43161dc56a08ffd0727df1516c987f7b187f5194c6
```

### SHA-256 Hashes

- SHA-256 produces hexadecimal outputs (0-9, a-f).
- 1 leading zero = ~16 tries
- 2 leading zeroes = ~256 tries
- 19 leading zeroes = ~75 quindecillion tries (7.55×10⁴⁶)

Each additional zero increases the average attempts exponentially.

---

## 📜 Pseudocode of Mining Algorithm

```
while True:
    data = prev_block_header + new_transactions
    nonce = 0
    while True:
        hash = SHA256(data + nonce)
        if hash < target_difficulty:
            broadcast new block
            break
        nonce += 1
```

---

## 💰 Why Do Miners Do It?

Miners spend real-world resources:

- Electricity
- Specialized hardware (ASICs, GPUs)

In return, they are rewarded with:

- Block rewards (newly minted coins)
- Transaction fees

💡 The incentive ensures that miners secure the network and follow the rules.

---

## 🛡️ Network Security via PoW

- The need for computational work makes attacks expensive.
- Invalid blocks are rejected by nodes.
- Majority following consensus = a secure and trustworthy ledger.

---

## ✅ Summary

- **Proof-of-Work** ensures that blockchain participants follow agreed-upon rules without needing a central authority.
- **Mining** is the process by which blocks are created and validated via solving hash puzzles.
- The system is secured by **difficulty, verification, and incentives**.

PoW networks like Bitcoin rely on miners to secure the chain, validate transactions, and maintain decentralization — all through computational effort.

---

# 🧠 Proof of Work & Mining Cheatsheet

## 🧩 What Is Proof of Work?

Proof-of-work (PoW) is a **consensus mechanism** that allows decentralized networks like Bitcoin (and previously Ethereum) to **agree on the state of the blockchain** without needing a central authority.

### Goals of PoW:
- Prevent **double spending**
- Ensure **validity** of blocks
- Maintain **agreement** among nodes in a decentralized network

---

## 🌐 Blockchain Nodes

- Blockchain networks are **distributed and decentralized databases**
- Each node is a computer participating in the network
- Nodes must agree on:
  - Current and future **account balances**
  - Order and **validity of transactions**

---

## 🔧 Consensus Mechanisms

> **Consensus = General Agreement**

- In blockchain, consensus means **51% or more** of nodes agree on the global state
- **Rules define what is valid**
- PoW is one of several consensus mechanisms (another is Proof of Stake)

### PoW Core Rules:
- ❌ You cannot double spend
- 📏 The **longest chain** (with most cumulative work) is considered the valid chain  
  → This is called **Nakamoto Consensus**

---

## ⛏️ What Is Mining?

Mining is the process of **adding new blocks** of valid transactions to the blockchain.

- Mining = the actual **"work"** in Proof of Work
- Miners are nodes that run **mining software**
- Miners:
  - Select valid transactions
  - Attempt to **solve a cryptographic puzzle**
  - Present their **proof-of-work**
  - Get rewarded if successful

---

## 🔐 Proof of Work Explained

Miners must find a hash that satisfies a certain **target difficulty**:

Example valid hash:
**000000000000000000043f43161dc56a08ffd0727df1516c987f7b187f5194c6**


- This output has **19 leading zeroes** (very hard to find!)
- The hash must be:
  - From valid input data (prev block header + transactions)
  - Less than the current **target difficulty**

---

## 🔁 Hashing & Difficulty

- Bitcoin and Ethereum (PoW era) use the **SHA-256** hash function
- Output is in **hexadecimal** → 16 possibilities per digit (0-9 + a-f)

### Example:
- 1 leading zero → average 16 tries
- 2 leading zeroes → 256 tries (16×16)
- 19 leading zeroes → ~75 quindecillion (!!!) attempts on average

---

## 🧮 PoW Mining Algorithm

1. 📦 Take current block's header + mempool transactions
2. ➕ Append a **nonce** (start with nonce = 0)
3. 🔁 Hash the data from steps 1 & 2
4. 🔍 Compare hash to **target difficulty**
5. ✅ If hash < target → puzzle solved → new block added
6. ❌ Else → increment nonce and repeat

---

## 🛡️ Why PoW Secures the Blockchain

- Miners must **expend real resources** (electricity, time, hardware)
- There’s no shortcut — it’s computationally expensive to cheat
- As long as the **majority follow rules**, the network remains:
  - Secure
  - Valid
  - Trustworthy

---

## 🎁 Incentives for Miners

Miners are rewarded with **cryptocurrency** for:

- Performing work
- Securing the network
- Adding valid blocks

This reward system aligns incentives and keeps the network running securely.

---

## ✅ Conclusion

Proof-of-Work ensures network consensus through **energy expenditure** and **computational effort**.

> Miners must present a valid **hash output** as proof they did the work to extend the blockchain.

As long as most miners act honestly, the blockchain remains **immutable**, **secure**, and **decentralized**.

---


# 🔐 Hashing and Proof of Work Cheatsheet

## 📌 What is Proof of Work?

**Proof of Work (PoW)** is a mechanism that requires computers to solve **computationally difficult problems** in order to perform a task—such as sending a message or adding a block to a blockchain.

---

## 🧠 Why Is PoW Important?

- 🌐 Secures decentralized networks like Bitcoin  
- 🚫 Prevents spam and abuse  
- 💰 Incentivizes participation via mining rewards  
- 🛡️ Makes altering the blockchain computationally infeasible  

---

## 💡 Origins of PoW

Proof of Work was first explored as a way to fight **email spam** by requiring senders to solve a small computation problem before sending a message.

### Example: Find a hash starting with `555`

<pre>
sha256("0");      // 5feceb...
sha256("1");      // 6b86b2...
sha256("2");      // d4735e...
// keep on guessing...
sha256("5118");   // 555850... ✅ Found it!
</pre>

- Hard to find  
- Easy to verify  
- Difficulty increases exponentially with more leading characters (e.g., `5555`, `55555`, etc.)

---

## 🧾 Use Case: Anti-Spam

Make each message computationally expensive to send.

If a user wants to send an email, they must find a hash of:

- The **message**
- The **recipient's address**
- A **nonce**

### Example:

<pre>
sha256("Hi Grandma! coolgrandma555@hotmail.com 0");   // f2d9e2...
sha256("Hi Grandma! coolgrandma555@hotmail.com 1");   // 4ee36e...
sha256("Hi Grandma! coolgrandma555@hotmail.com 2");   // c25e5c...
// ...
sha256("Hi Grandma! coolgrandma555@hotmail.com 424"); // 5552ab... ✅
</pre>

- 🧑 One-time effort for the sender  
- 🛑 Expensive for spammers at scale

---

## 🔁 What is a Nonce?

- A **nonce** is a number used once to vary the input
- It is incremented to try different hashes
- Used to "guess" the right hash output
- Critical in Proof of Work and mining

---

## ⚙️ How Bitcoin Uses Proof of Work

Bitcoin uses PoW to **secure the network** and validate blocks.

### Process:

1. ⛏️ Miners collect unconfirmed transactions  
2. 🧱 Create a candidate block  
3. 🔄 Add a nonce to the block data  
4. 🔐 Hash the block header  
5. ✅ Check if the hash is below a target threshold  
6. 🪙 If successful, add the block to the blockchain and receive a reward  
7. 🔁 If not, repeat with a new nonce  

---

## 🛡️ Why is it Secure?

- Thousands of nodes compete to solve the PoW  
- The first to succeed **adds the next block**  
- To attack the network, you'd need more hash power than all others combined (a **51% attack**)

### Even with 51% control:

- You could delay or reorder transactions  
- You **cannot** rewrite large parts of history easily  
- It's extremely expensive and detectable

---

## 🧠 Summary

- **PoW** = effort-based mechanism to ensure fairness and prevent abuse  
- Used in **Bitcoin** to secure transactions and blocks  
- Involves **hashing** and **nonces**  
- Makes networks **resilient**, **transparent**, and **tamper-resistant**  
- Attacks are possible but **impractical** due to high cost and difficulty

---


# 📘 Supplemental Resources on Proof of Work

---

## 🕰️ History of Proof of Work

### Adam Back and HashCash
- **HashCash** was proposed by **Adam Back** as a way to prevent email spam.
- It required the sender to compute a hash that met certain criteria, making mass spam expensive and inefficient.

### Cypherpunk Contributions
- Shared via the **Cypherpunk mailing list**, HashCash inspired further developments:

#### Hal Finney: Reusable Proofs of Work
- Extended HashCash by proposing **Reusable Proofs of Work (RPOW)**.
- Allowed a proof-of-work to be passed and reused in a decentralized way.

#### Wei Dai: B-Money
- Proposed a theoretical cryptocurrency system named **B-Money**.
- Also built on the concept of proof-of-work from HashCash.

---

## ⛏️ Bitcoin Mining

### Role of Mining
- Bitcoin uses **Proof of Work** as a decentralized method for confirming transactions.
- **Mining** is the act of competing to solve computational puzzles in order to add blocks to the blockchain.

### Mining Characteristics
- Blocks are mined **approximately every 10 minutes**.
- This is subject to variance based on random hash discovery.

### Difficulty Adjustment
- The **target difficulty** changes every 2016 blocks (about every 2 weeks).
- This adjustment ensures block production remains roughly 10 minutes, regardless of total network hash power.
- When more miners join, the difficulty increases.
- When miners leave, the difficulty decreases.

---

## 🧑‍🤝‍🧑 Mining Pools

### What Are Mining Pools?
- Mining pools are groups of miners who combine their hash power.
- They share block rewards proportionally based on contributed work.
- This results in **smaller but more frequent payouts**.

### Why Use Mining Pools?
- Reduces payout variance.
- More predictable and steady income compared to solo mining.
- Useful for miners with less powerful hardware.

### Learn More
- 📌 You can check the current **Bitcoin coinbase reward** [here](https://www.blockchain.com/charts/coinbase-size).
- 📊 For a comprehensive comparison of mining pools, refer to [this document](https://en.bitcoin.it/wiki/Comparison_of_mining_pools).

---

# Blockchain Structure Cheatsheet

Blockchains are fancy databases designed for decentralized systems. Let's explore the key concepts behind blockchain architecture and how it differs from traditional databases.

---

## Blockchain Architecture

A **blockchain** is a **distributed database** made up of a chain of validated blocks. Each block:

- Contains transaction data
- Is cryptographically linked to the previous block

This creates a **"chain"** of blocks — hence, **blockchain**.

### Nodes

- Nodes are individual computers or devices participating in the blockchain network.
- Each node stores a copy of the blockchain.
- No single node has authority — they all function **equally**.
- This forms a **peer-to-peer (P2P)** network.

---

## Centralized vs Peer-to-Peer

### Centralized Network

- One server maintains the state.
- All other clients must rely on that central server.

### Peer-to-Peer Network

- No central server.
- Every node maintains a full copy of the data.
- Every node can validate and propose changes to the blockchain.

---

## Consensus Mechanism

**Question:**  
How do distributed nodes agree on valid data **without** a central authority?

**Answer:**  
They use **consensus mechanisms**.

### Example: Bitcoin

Bitcoin uses **Proof of Work (PoW)**. Nodes (miners) compete to solve a mathematical puzzle. The first to solve it earns the right to add a new block.

This addresses the **Byzantine Generals Problem** — ensuring agreement in a decentralized system with potentially malicious actors.

---

## Blockchain Demo

Visit: [https://blockchaindemo.io](https://blockchaindemo.io)

The demo walks through the creation and structure of a blockchain.

---

## Genesis Block

- The **genesis block** is the **first block** in a blockchain.
- It has:
  - `index = 0`
  - `previous hash = "0"`

---

## Block Structure

Each block stores:

- `index`: position in the chain
- `timestamp`: creation time (usually in UNIX format)
- `previous hash`: hash of the previous block
- `data`: contents of the block (e.g., transactions)
- `nonce`: number used to find a valid hash
- `hash`: digital fingerprint of the block (not stored inside the block)

---

## Hashing Function

A **hashing function** takes block data and produces a unique digital fingerprint:


**f(index + previousHash + timestamp + data + nonce) = hash**

Example:

f(0 + "0" + 1508270000000 + "Welcome to Blockchain Demo 2.0!" + 604)
= 000dc75a315c77a1f9c98fb6247d03dd18ac52632d7dc6a9920261d8109b37cf


---

## Valid Hash

A **valid hash** is one that meets a set difficulty — often defined by the number of leading zeros.

Example:

- Valid hash must start with `000`
- More zeros = higher **difficulty**

### Mining

- Miners change the `nonce` until a valid hash is found.
- This is computationally intensive and called **mining**.

---

## Data Integrity

### Question:  
How do blockchains ensure data isn't corrupted or tampered with?

### Answer:  
Because each block’s hash depends on its data, changing the data changes the hash.

Consequences of altering a block:

1. Hash becomes invalid (no longer meets difficulty).
2. All following blocks break, since their `previous hash` is now incorrect.
3. Attacker must **re-mine** all subsequent blocks — computationally infeasible.

Example:

Original Genesis Block Hash:
000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f

Altered Hash:

eb3e5df5eefceb8950e4a444507ce7df1cc534f54a5113f2792ab64830392db0


Mallory would need to:

1. Find a new valid hash for the altered block.
2. Recalculate and re-mine **every** subsequent block.
3. Do all of this **faster** than the rest of the network.

Attack fails. ✅ Data integrity holds.

---

## Adding a New Block

To add a new block, the following conditions must be met:

1. `index` is one greater than the previous block.
2. `previous hash` matches the last block’s hash.
3. `hash` is correctly calculated.
4. `hash` meets the difficulty requirement.

---

## Peer-to-Peer Validation

Every node in the P2P network validates each proposed block.

- All nodes apply the same consensus rules.
- If valid, the block is added to their own copy.
- All copies remain synchronized without central control.

---

## Conclusion

Blockchains are:

- **Decentralized**
- **Distributed**
- **Secure**
- **Resistant to tampering**

Through consensus mechanisms like Proof of Work and the structure of the chain itself, blockchain maintains data integrity without a central administrator.

---

