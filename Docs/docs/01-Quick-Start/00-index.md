# Quick Start

The quick start guide is showing you how to use TLS-Anvil to test a TLS server or client.
This is basically a two step process.

First TLS-Anvil is executed to perform the tests against the OpenSSL example server and client.
We will use OpenSSL as an example implementation here.
TLS-Anvil as well as the OpenSSL server/client will run inside a Docker container.
The OpenSSL server/client images are provided by the TLS-Docker-Library project which we released alongside TLS-Anvil.
So see how you can test against other implementations that are inside the TLS-Docker-Library see [Using the TLS-Docker-Library](/docs/Docker-Library).

The second step is to analyze the results.
Those are going to be imported into a web application that visualizes the results for each test case.
The application is also able to inspect every connection between TLS-Anvil and the tested target at TCP message level.

### Requirements

- Docker
- Python *(optional, for using TLS-Docker-Library to test other implementations)*

### GitHub Repositories

- [TLS-Anvil](https://github.com/tls-attacker/tls-anvil) (Testsuite)
- [TLS-Docker-Library](https://github.com/tls-attacker/tls-docker-library) *(optional, images of TLS implementations)*
- [Anvil-Web](https://github.com/tls-attacker/anvil-web) *(optional, for a graphical user interface and to analyze reports)*

