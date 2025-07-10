# Client Testing

This site demonstrates how to test the OpenSSL client provided by the TLS-Docker-Library.
You can of course also test other implementations, for example by [using the TLS-Docker-Library](/docs/Docker-Library) or by running your own client binary.

Testing the client in the most simple form roughly takes around 15 minutes.
However, this duration can increase to several depending on the strength parameter that basically defines how often a single test case is performed with different parameters.

### Preparations

Similar to the server test we first create a dedicated docker network that is used by the TLS-Anvil and OpenSSL client container to communicate with each other. If it is already created, no need to recreate it.

```bash
docker network create tls-anvil
```

### Starting the TLS-Anvil container

Since the client has to connect to TLS-Anvil the test suite container is started first.
After starting, the testsuite is waiting for the client to connect, so leave the terminal open.

```bash showLineNumbers
docker run \
    --rm \
    -it \
    --network tls-anvil \
    --name tls-anvil \
    -v $(pwd):/output/ \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -zip \
    -parallelHandshakes 3 \
    -parallelTests 3 \
    -strength 1 \
    -identifier openssl-client \
    client \
    -port 8443 \
    -triggerScript curl --connect-timeout 2 openssl-client:8090/trigger
```

* Lines 2-5: Docker related command flags
* Line 6: Set the output directory through a docker volume
* Line 7: Specifies the TLS-Anvil docker image
* Line 8: Zip the results, that way we can easily import them into Anvil-Web later
* Lines 9-10: Since the client can started multiple times, TLS-Anvil can run multiple tests and handshakes in parallel
* Line 11: Defines the strength, i.e. the `t` for t-way combinatorial testing
* Line 12: Defines an arbitrary name that is written to the report
* Line 13: We want to test a client
* Line 14: The port on which TLS-Anvil listens to accept requests from the client
* Line 15: Specifies a script that is executed before each handshake, which the goal to trigger a connection from the client. See below how this works.

### Starting the OpenSSL client container

:::info

As mentioned before, we use OpenSSL as an example.
The OpenSSL client image in this example is prebuilt using the [TLS-Docker-Library](https://github.com/tls-attacker/tls-docker-library). The entrypoint of the client images is a small HTTP server that provides two REST-API endpoints on port 8090.
* `GET /trigger` starts the client
* `GET /shutdown` shutdown the HTTP server to terminate the container

:::

Starting the client can be done with the following command. This will download a pre-built image from our GitHub registry, and run it.
Since TLS-Anvil is already running, open another terminal to start the client.

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
* Line 6: Specifies the OpenSSL client image from the TLS-Docker-Library
* Line 7: This is passed to the OpenSSL `s_client` binary, which is started each time a HTTP-GET request is sent to `:8090/trigger`.

### What now?
After the testsuite finished you should see a folder named `Results_...` which contains all the results.
To analyze them, go to the next page.