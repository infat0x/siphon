# Pattern Database (`scanner/patterns.go`)

The `patterns.go` module contains Siphon's massive, core database of Regular Expressions used to identify secrets, tokens, and keys across hundreds of different services.

## Overview

This file is the brain of the `regex.go` scanner. It maps human-readable secret names to highly tuned Regular Expressions.

> [!NOTE]
> Siphon v7 contains over 500 distinct patterns, covering everything from AWS, GCP, and Azure, to Stripe, PayPal, and regional banking APIs.

## False Positive Reduction

The single most important variable in this file is `FalsePositiveRe`. This is a massive regular expression that matches common MIME types, CSS properties, open-source library names, and standard JavaScript keywords.

```go
var FalsePositiveRe = `(?i)(application/(json|xml|javascript...)|text/(html...)|...|console\.|document\.)`
```

Any matched secret that also matches this false-positive regex is instantly discarded.

## Pattern Categories

The `SecretPatterns` map is categorized into several domains:

1. **Cloud & Infra**: AWS Keys, GCP Service Accounts, Azure Connection Strings.
2. **Banking & PCI**: PANs, IBANs, SWIFT codes, and regional banks (e.g., AZ Kapital Bank, AZ ABB).
3. **Comms & Messaging**: Slack Tokens, Discord Webhooks, Twilio SIDs.
4. **Social & OAuth**: Facebook App Secrets, Twitter Tokens, Google OAuth.
5. **Database Connections**: PostgreSQL URIs, MongoDB Atlas strings, Redis passwords.
6. **Crypto & Web3**: Ethereum Private Keys, Solana Keys, Mnemonic Phrases.
7. **Private Keys**: RSA, EC, DSA, OpenSSH, PGP.

> [!TIP]
> The database includes the complete Mazen160 secrets-patterns-db as a baseline, heavily augmented with modern 2024/2025 service patterns (like Clerk, Resend, Supabase, and Turso).
