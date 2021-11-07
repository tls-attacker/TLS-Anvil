# TLS-Testsuite

The TLS-Testsuite is powered by the [TLS-Test-Framework](https://github.com/RUB-NDS/TLS-Test-Framework) and was developed as part of the master's thesis *Development and Evaluation of a TLS-Testsuite* at the *Ruhr-University Bochum* in cooperation with the *TÜV Informationstechnik GmbH*.

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
git clone git@github.com:RUB-NDS/ModifiableVariable.git
( cd ModifiableVariable && git checkout 48a847247af1b028ced1caea479fd2297f57512d )

git clone https://github.com/RUB-NDS/ASN.1-Tool
( cd ASN.1-Tool && git checkout 49c9d809954cf841ef21beeda1b0fbda9a771f51 ) 

git clone git@github.com:RUB-NDS/X509-Attacker.git
( cd X509-Attacker && git checkout b499437151b3616eb9b767b19ba6ce700f0771a2 )

git clone git@github.com:RUB-NDS/TLS-Attacker-Development.git
( cd TLS-Attacker-Development && git checkout 66adcc9c1b794ff90b158040a694d678bdf4da4c )

git clone git@github.com:RUB-NDS/TLS-Scanner-Development.git
( cd TLS-Scanner-Development && git checkout f2170ed04f3623d5ce9f89dab43d984225e14817 && git submodule update --init --recursive )

git clone git@github.com:RUB-NDS/TLS-Test-Framework.git
( cd TLS-Test-Framework && git checkout c85fbf2a4daa9ce0361f56fdfe58ae3d14bf1d47 )

git clone git@github.com:RUB-NDS/TLS-Testsuite.git
( cd TLS-Testsuite && git checkout 2d11b29c2455c33c8d01e78b56497495960f765a )

docker build -f TLS-Testsuite/Dockerfile . -t testsuite
```

## Run
```
docker run --rm -it testsuite --help
```

