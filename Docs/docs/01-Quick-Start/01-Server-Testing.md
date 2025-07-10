# Server Testing

This site demonstrates how to test an OpenSSL server provided by the TLS-Docker-Library.
You can of course also test other implementations, for example by [using the TLS-Docker-Library](/docs/Docker-Library) or by running your own server binary.

Testing the server in the most simple form roughly takes around 10-20 minutes.
However, this duration can increase to several depending on the strength parameter that basically defines how often a single test case is performed with different parameters.

### Preparations

:::info

The server image we will use, is prebuilt by us using the [TLS-Docker-Library](https://github.com/tls-attacker/tls-docker-library).
We included certificates in the container, so that you do not have to generate them yourself.

:::

For better compatibility, we create a dedicated docker network that is used by TLS-Anvil and the OpenSSL server container to communicate with each other.

```bash
docker network create tls-anvil
```

### Starting the OpenSSL Server

:::info

As mentioned before, we use OpenSSL as an example. In this case the server uses an RSA certificate. However, TLS-Anvil works with any certificate and automatically adapts the tests to the given circumstances.

:::

Starting the server can be done with the following command. This will download a pre-built image from our GitHub registry, and run it.

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

After that, TLS-Anvil is started. The current directory is mounted to the docker container and used to store the results. We connect to the server using its docker hostname `openssl-server`, which is possible since they are on the same docker network.

```bash showLineNumbers
docker run \
    --rm \
    -it \
    --name tls-anvil \
    --network tls-anvil \
    -v $(pwd):/output/ \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -zip \
    -parallelHandshakes 1 \
    -connectionTimeout 200 \
    -strength 1 \
    -identifier openssl-server \
    server \
    -connect openssl-server:8443
```

* Lines 2-5: Docker related command flags
* Line 6: Set the output directory through a docker volume
* Line 7: Specifies the TLS-Anvil docker image
* Line 8: Zip the results, that way we can easily import them into Anvil-Web later
* Line 9: Since the OpenSSL example server is single threaded, we can only perform one handshakes sequentially
* Line 10: We run our server locally, so we can reduce the timeout to 200ms.
* Line 11: Defines the strength, i.e. the `t` for t-way combinatorial testing
* Line 13: We want to test a server
* Line 14: Determines the details how TLS-Anvil should connect to the server

### What now?
After the testsuite finished you should see a folder named `Results_...` which contains all the results.
To analyze them, go to [Viewing Results](Anvil-Web).