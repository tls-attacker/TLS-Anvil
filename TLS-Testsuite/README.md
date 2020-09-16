# TLS-Testsuite

The TLS-Testsuite is powered by the [TLS-Test-Framework](https://github.com/RUB-NDS/TLS-Test-Framework) and was developed as part of the master's thesis *Development and Evaluation of a TLS-Testsuite* at the *Ruhr-University Bochum* in cooperation with the *TÜV Inormationstechnik GmbH*.

The Testsuite contains around 175 client and server tests for TLS 1.2 and TLS 1.3 covering the following RFCs:
* RFC 4492 - Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
* RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2
* RFC 6066 - Transport Layer Security (TLS) Extensions: Extension Definitions
* RFC 6176 - Prohibiting Secure Sockets Layer (SSL) Version 2.0
* RFC 7366 - Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
* RFC 7465 - Prohibiting RC4 Cipher Suites
* RFC 7507 - TLS Fallback Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks
* RFC 7568 - Deprecating Secure Sockets Layer Version 3.0
* RFC 7685 - A Transport Layer Security (TLS) ClientHello Padding Extension
* RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
* RFC 8701 - Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility

The RFCs are available as PDF in the `RFCs` subfolder. The PDF files are annotated to keep track for which parts of the RFCs tests are already implemented.

## Connected Projects
* [TLS-Test-Framework](https://github.com/RUB-NDS/TLS-Test-Framework)
* [TLS-Testsuite-Report-Analyzer](https://github.com/RUB-NDS/TLS-Testsuite-Report-Analyzer)
* [TLS-Testsuite-Large-Scale-Evaluator](https://github.com/RUB-NDS/TLS-Testsuite-Large-Scale-Evaluator)

## Build
To build this project the following script needs to be executed:
```shell
git clone https://github.com/RUB-NDS/ASN.1-Tool
cd ASN.1-Tool && git checkout 49c9d809954cf841ef21beeda1b0fbda9a771f51 

git clone git@github.com:RUB-NDS/X509-Attacker.git
cd X509-Attacker && git checkout b499437151b3616eb9b767b19ba6ce700f0771a2

git clone git@github.com:RUB-NDS/TLS-Attacker-Development.git
cd TLS-Attacker-Development && git checkout 281c566d7b98809f3ab72cf17315be1b5afee1d0

git clone git@github.com:RUB-NDS/TLS-Scanner-Development.git
cd TLS-Scanner-Development && git checkout f2170ed04f3623d5ce9f89dab43d984225e14817

git clone git@github.com:RUB-NDS/TLS-Test-Framework.git
cd TLS-Test-Framework && git checkout 2a1e943018ad3eeea44e3f67d22b542460fe8e6c

git clone git@github.com:RUB-NDS/TLS-Testsuite.git
cd TLS-Testsuite && git checkout cc117ead7cfb6000690eb1533d8dc96b0e1fa8db

docker build -f TLS-Testsuite/Dockerfile . -t testsuite
```

## Run
```
docker run --rm -it testsuite --help
```

