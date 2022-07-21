
# Quick Start

The quick start guide is showing you how to use TLS-Anvil to test a TLS server or client. This is basically a two step process. First TLS-Anvil is executed to perform the tests against the OpenSSL example server and client. TLS-Anvil as well as the OpenSSL server/client will run inside a Docker container. The TLS server/client images are provided by the TLS-Docker-Library project which we released alongside TLS-Anvil.

The second step is to analyze the results. Those are going to be imported into a web application that visualizes the results for each test case. The application is also able to inspect every connection between TLS-Anvil and the tested target at TCP message level.

### Requirements
- Docker

