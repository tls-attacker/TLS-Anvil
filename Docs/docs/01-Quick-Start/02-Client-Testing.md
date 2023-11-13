# Client Testing

This site demonstrates how to test the OpenSSL client provided by the TLS-Docker-Library.
Testing the client in the most simple form roughly takes around 15 minutes. However, this duration can increase to several depending on the strength parameter that that basically defines how often a single test case triggered with different parameters.

### Preperations

Similar to the server test we first create a dedicated docker network that is used by the TLS-Anvil and OpenSSL client container to communicate with each other.

```bash
docker network create tls-anvil
```

### Starting the TLS-Anvil container

Since the client has to connect to TLS-Anvil the test suite container is started first.

```bash showLineNumbers
docker run \
    --rm \
    -it \
    -v $(pwd):/output/ \
    --network tls-anvil \
    --name tls-anvil \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -outputFolder ./ \
    -parallelHandshakes 3 \
    -parallelTests 3 \
    -strength 1 \
    -identifier openssl-client \
    client \
    -port 8443 \
    -triggerScript curl --connect-timeout 2 openssl-client:8090/trigger
```

* Lines 2-6: Docker related command flags
* Line 7: Specifies the TLS-Anvil docker image
* Lines 9-10: Since the client can started multiple times, TLS-Anvil can run multiple tests and handshakes in parallel
* Line 11: Defines the strength, i.e. the `t` for t-way combinatorial testing
* Line 12: Defines an arbitrary name that is written to the report
* Line 13: We want to test a client
* Line 14: The port on which TLS-Anvil listens to accept requests from the client
* Line 15: Specifies a script that is executed before each handshake, which the goal to trigger a connection from the client. See below how this works.

### Starting the OpenSSL client container

The OpenSSL client image is provided by the TLS-Docker-Library. The entrypoint of the client images is a small HTTP server that provides two REST-API endpoints on port 8090.
* `GET /trigger` starts the client
* `GET /shutdown` shutdown the HTTP server to terminate the container

```bash showLineNumbers
docker run \
    -d \
    --rm \
    --name openssl-client \
    --network tls-anvil \
    ghcr.io/tls-attacker/openssl-client:1.1.1i \
    -connect tls-anvil:8443
```

* Lines 2-5: Docker related command flags
* Line 7: Specifies the OpenSSL client image from the TLS-Docker-Library
* Line 8: This is passed to the OpenSSL `s_client` binary, which is started each time a HTTP-GET request is sent to `:8090/trigger`.

