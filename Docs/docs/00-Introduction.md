# Introduction

Welcome to **TLS-Anvil**, our comprehensive test suite for testing (D)TLS 1.2 and 1.3 servers and clients.  
TLS-Anvil currently includes approximately 400 test cases based on requirements derived from various TLS-related RFCs, as well as from known past attacks.

The tests are implemented in Java using **JUnit**, **coffee4j**, and **TLS-Attacker**, and are designed to detect deviations from the TLS specification in both servers and clients.

---

### RFCs Covered by the Test Suite

* [RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246) — The Transport Layer Security (TLS) Protocol Version 1.2
* [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) — The Transport Layer Security (TLS) Protocol Version 1.3
* [RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701) — Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility
* [RFC 7507](https://datatracker.ietf.org/doc/html/rfc7507) — TLS Fallback Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks
* [RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066) — TLS Extensions: Extension Definitions
* [RFC 7568](https://datatracker.ietf.org/doc/html/rfc7568) — Deprecating Secure Sockets Layer Version 3.0
* [RFC 7919](https://datatracker.ietf.org/doc/html/rfc7919) — Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for TLS
* [RFC 7465](https://datatracker.ietf.org/doc/html/rfc7465) — Prohibiting RC4 Cipher Suites
* [RFC 7366](https://datatracker.ietf.org/doc/html/rfc7366) — Encrypt-then-MAC for TLS and DTLS
* [RFC 8422](https://datatracker.ietf.org/doc/html/rfc8422) — ECC Cipher Suites for TLS Versions 1.2 and Earlier
* [RFC 7685](https://datatracker.ietf.org/doc/html/rfc7685) — ClientHello Padding Extension
* [RFC 6176](https://datatracker.ietf.org/doc/html/rfc6176) — Prohibiting SSL Version 2.0
* [RFC 7457](https://datatracker.ietf.org/doc/html/rfc7457) — Summary of Known Attacks on TLS and DTLS
* [RFC 6347](https://datatracker.ietf.org/doc/html/rfc6347) — Datagram Transport Layer Security Version 1.2
