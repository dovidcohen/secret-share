# Security Policy

Secret Share is a security product; reports are taken seriously and handled quickly.

## Reporting a vulnerability

Please use **GitHub's private vulnerability reporting**: go to the repository's
[Security tab → Report a vulnerability](https://github.com/dovidcohen/secret-share/security/advisories/new).
Do **not** open a public issue for security problems.

You can expect an acknowledgement within a few days. Please include reproduction
steps and the impact you believe the issue has.

## Scope

In scope:

- Anything that lets a party other than the intended receiver obtain a secret
  (cryptographic flaws, key-derivation weaknesses, MITM of the live transfer,
  read-once bypasses, drop enumeration).
- The server learning more than it should (plaintext, key material, the word
  portion of share codes).
- Authentication bypasses on claim/revoke, rate-limit or burn-counter bypasses.

Out of scope:

- The inherent web-delivery trust model (you trust the JavaScript served at time
  of use) — documented in the README; reports about it without a novel attack
  are not actionable.
- Denial of service via volume, social engineering, or issues requiring a
  compromised device or browser.

## Design notes for researchers

The protocol and threat model are documented in the [README](README.md#security-model-honestly-stated).
Key facts: codes carry ~65 bits of entropy in 5 EFF-wordlist words, keys derive via
Argon2id (64 MiB, t=3) salted per-mailbox, blobs are AES-256-GCM, the live path
re-encrypts under per-session keys with mutual HMAC key-confirmation before any
secret bytes flow, and the server stores only ciphertext and hashed auth tags.

No bug bounty is offered at this time; good-faith research is welcome and
credited in release notes if desired.
