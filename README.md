# TLS-Anvil
TLS-Anvil is a test suite for the evaluation of RFC compliance of Transport Layer Security (TLS) libraries using combinatorial testing (CT).

The test suite contains around 408 client and server tests for TLS 1.2 and TLS 1.3 based on the following RFCs:
* RFC 4492 - Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
* RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2
* RFC 6066 - Transport Layer Security (TLS) Extensions: Extension Definitions
* RFC 6176 - Prohibiting Secure Sockets Layer (SSL) Version 2.0
* RFC 7366 - Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
* RFC 7457 - Summarizing Known Attacks on Transport Layer Security (TLS) and Datagram TLS (DTLS)
* RFC 7465 - Prohibiting RC4 Cipher Suites
* RFC 7507 - TLS Fallback Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks
* RFC 7568 - Deprecating Secure Sockets Layer Version 3.0
* RFC 7685 - A Transport Layer Security (TLS) ClientHello Padding Extension
* RFC 7919 - Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
* RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
* RFC 8701 - Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility

## Project Structure
* TLS-Testsuite: Contains the test templates
* TLS-Test-Framework: Aggregator that combines coffee4j and implements JUnit extensions, annotations and the API for modeling tests for the TLS protocol
* Report-Analyzer: Standalone browser application that facilitates the analysis of TLS-Anvil's output 

## Build
To clone and build this project for docker, the following script needs to be executed:
```shell
git clone https://github.com/tls-attacker/ModifiableVariable.git
( cd ModifiableVariable && git checkout e1f537e6874e352c9284c5a6516b81118f26b754 )

git clone https://github.com/tls-attacker/ASN.1-Tool.git
( cd ASN.1-Tool-Development && git checkout 05370b36d6f0dcc0187472b1557eeba410ca3563 ) 

git clone https://github.com/tls-attacker/X509-Attacker.git
( cd X509-Attacker-Development && git checkout 77ce56af7b8fa951224bb1f47b5e637e365b7968 )

git clone https://github.com/tls-attacker/TLS-Attacker.git
( cd TLS-Attacker-Development && git checkout 0e94899fcf2673e540fb1dec37a3fbb2b3520381 )

git clone https://github.com/tls-attacker/TLS-Scanner.git
( cd TLS-Scanner-Development && git checkout f0780ea22664939ea42a31719cf30a3b9ce1bb7c && git submodule update --init --recursive )

git clone https://github.com/tls-attacker/TLS-Anvil.git

docker build -f TLS-Anvil/Dockerfile . -t tlsanvil
```

## Run
```
docker run --rm -it tlsanvil -help
```

The foundation of TLS-Anvil was developed as part of the master's thesis *Development and Evaluation of a TLS-Testsuite* by Philipp Nieting at *Ruhr University Bochum* in cooperation with the *TÜV Informationstechnik GmbH*.


