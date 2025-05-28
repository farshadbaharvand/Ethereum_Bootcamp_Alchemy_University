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
