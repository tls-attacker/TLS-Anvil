# Quick Start

This quick start guide demonstrates how to use **TLS-Anvil** to test a TLS server or client.  
The process involves two main steps.

First, TLS-Anvil is executed to run tests against an example TLS server and client based on OpenSSL.  
Both TLS-Anvil and the OpenSSL server/client run inside Docker containers.

The OpenSSL server/client images are provided by the **TLS-Docker-Library** project, which was released alongside TLS-Anvil.  
To learn how to test against other implementations available in the TLS-Docker-Library, refer to [Using the TLS-Docker-Library](/docs/Docker-Library).

The second step is analyzing the test results.  
These results are imported into a web application that visualizes the outcomes of each test case.  
The application also allows inspection of every connection between TLS-Anvil and the target implementation at the TCP message level.

### Requirements

- Docker
- Python *(optional — required only if using TLS-Docker-Library to test other implementations)*

### GitHub Repositories

- [TLS-Anvil](https://github.com/tls-attacker/tls-anvil) — Test suite
- [TLS-Docker-Library](https://github.com/tls-attacker/tls-docker-library) *(optional — Docker images of various TLS implementations)*
- [Anvil-Web](https://github.com/tls-attacker/anvil-web) *(optional — graphical user interface for analyzing test reports)*
