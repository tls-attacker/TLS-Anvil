# Server Testing

This site demonstrates how to test the OpenSSL server provided by the TLS-Docker-Library.
Testing the server in the most simple form roughly takes around 5 minutes. However, this duration can increase to several depending on the strength parameter that that basically defines how often a single test case triggered with different parameters.

### Preperations

Before the server is able to do anything we need to generate a TLS certificate.

```bash
./TLS-Docker-Library/setup.sh
```

Next we create a dedicated docker network that is used by the TLS-Anvil and OpenSSL server container to communicate with each other.

```bash
docker network create tls-anvil
```

### Starting the OpenSSL Server

As mentioned before, we use OpenSSL as an example. In this case the server uses an RSA certificate. However, TLS-Anvil works with any certificate and automatically adapts the tests to the given circumstances.

```bash showLineNumbers
docker run \
    -d \
    --rm \
    --name openssl-server \
    --network tls-anvil \
    -v cert-data:/certs/ \
    ghcr.io/tls-attacker/openssl-server:1.1.1i \
    -port 8443 \
    -cert /certs/rsa2048cert.pem \
    -key /certs/rsa2048key.pem
```

* Lines 2-6: Docker related command flags
* Line 7: Specifies the Docker image from the TLS-Docker-Library
* Lines 8-10: Those flags are passed to the OpenSSL `s_server` binary

### Starting TLS-Anvil

Finally TLS-Anvil is started. The current directory is mounted to the docker container and used to store the results.

```bash showLineNumbers
docker run \
    --rm \
    -it \
    -v $(pwd):/output/ \
    --name tls-anvil \
    --network tls-anvil \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -outputFolder ./ \
    -parallelTestCases 1 \
    -strength 1 \
    -identifier openssl-server \
    server \
    -connect openssl-server:8443 \
    -doNotSendSNIExtension
```

* Lines 2-6: Docker related command flags
* Line 7: Specifies the TLS-Anvil docker image
* Line 9: Since the OpenSSL example server is single threaded, we can only perform one handshakes sequentially
* Line 10: Defines the strength, i.e. the `t` for t-way combinatorial testing
* Line 12: We want to test a server.
* Line 13-14: Determines the details how TLS-Anvil should connect to the server.

