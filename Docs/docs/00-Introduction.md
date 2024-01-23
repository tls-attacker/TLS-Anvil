# Introduction

Welcome to TLS-Anvil, our test suite for (D)TLS 1.2 and 1.3 servers and clients. TLS-Anvil currently includes around 400 test cases that are based on requirements derived from various TLS related RFCs listed below as well as attacks from the past. The tests are implemented in Java using JUnit, coffee4j and TLS-Attacker and aim to detect violations of the TLS specification by TLS servers or clients.

**RFCs covered by tests:**
* [RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246) - The Transport Layer Security (TLS) Protocol Version 1.2
* [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) - The Transport Layer Security (TLS) Protocol Version 1.3
* [RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701) - Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility
* [RFC 7507](https://datatracker.ietf.org/doc/html/rfc7507) - TLS Fallback Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks
* [RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066) - Transport Layer Security (TLS) Extensions: Extension Definitions
* [RFC 7568](https://datatracker.ietf.org/doc/html/rfc7568) - Deprecating Secure Sockets Layer Version 3.0
* [RFC 7919](https://datatracker.ietf.org/doc/html/rfc7919) - Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
* [RFC 7465](https://datatracker.ietf.org/doc/html/rfc7465) - Prohibiting RC4 Cipher Suites
* [RFC 7366](https://datatracker.ietf.org/doc/html/rfc7366) - Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
* [RFC 8422](https://datatracker.ietf.org/doc/html/rfc8422) - Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
* [RFC 7685](https://datatracker.ietf.org/doc/html/rfc7685) - A Transport Layer Security (TLS) ClientHello Padding Extension
* [RFC 6176](https://datatracker.ietf.org/doc/html/rfc6176) - Prohibiting Secure Sockets Layer (SSL) Version 2.0
* [RFC 7457](https://datatracker.ietf.org/doc/html/rfc7457) - Summarizing Known Attacks on Transport Layer Security (TLS) and Datagram TLS (DTLS)
* [RFC 6347](https://datatracker.ietf.org/doc/html/rfc6347) - Datagram Transport Layer Security Version 1.2
