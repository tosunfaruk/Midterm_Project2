# Secure Backend System - Implementation Report

## 1. Why Salting is Necessary to Prevent "Rainbow Table" Attacks

A **Rainbow Table** is a massive, precomputed dictionary of plaintext passwords and their corresponding hash values. If a database stores passwords only as simple hashes (e.g., using pure MD5 or SHA-256), an attacker who gains access to the database can simply look up the stolen hashes in their Rainbow Table to instantly reveal the original plaintext passwords.

**Salting** solves this problem by adding a unique, random string of characters (the "salt") to each user's password *before* it is hashed. 

- Because the salt is entirely unique for every single user, two users with the exact same password (e.g., "password123") will have completely different resulting hashes in the database.
- To successfully use a Rainbow Table against salted hashes, an attacker would need to compute and store a separate, massive table for *every possible salt value*. This requires an impossible amount of storage and computational power. 

By forcing the attacker to compute hashes individually for each user, salting renders Rainbow Tables effectively useless and drastically improves the security of stored credentials.

---

## 2. Risks of Storing Sensitive Data Inside a JWT Payload

A JSON Web Token (JWT) is composed of three parts: Header, Payload, and Signature. While the signature guarantees that the token has not been tampered with or altered in transit, the payload itself is merely **Base64Url encoded, not encrypted.**

This means that anyone who intercepts or possesses the JWT can easily decode the payload and read its contents using public tools (like `jwt.io`). If sensitive data—such as passwords, credit card numbers, personal identification numbers (SSN), or private email addresses—is stored inside the JWT payload, it introduces severe risks:

- **Immediate Data Exposure:** Any malicious actor (or even third-party scripts running in the user's browser) that captures the token can read the sensitive data immediately, without needing any secret keys.
- **Privacy Violations & Least Privilege:** The principle of least privilege is violated since frontend applications or intermediate backend services might not need all that sensitive data, but it is exposed to them anyway.
- **Immutable Exposure:** Because JWTs are stateless and cannot easily be modified once issued, if sensitive data is placed in them, it remains exposed for the entire lifespan of the token.

**Mitigation:** The JWT payload should only contain non-sensitive, necessary identifiers (like a generic User ID, username, and role) and metadata (like expiration time). Any highly sensitive data should be retrieved securely from the backend database using the User ID on the server side, rather than being transported back and forth in the token.
