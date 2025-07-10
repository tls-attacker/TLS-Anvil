# Server Testing

This site demonstrates how to test an OpenSSL server provided by the TLS-Docker-Library.  
You can also test other implementations, for example by [using the TLS-Docker-Library](/docs/Docker-Library) or by running your own server binary.

Testing the server in its simplest form typically takes around 10-20 minutes.  
However, this duration may increase to several hours depending on the strength parameter, which defines how many times each test case is executed with varying parameters.

### Preparations

:::info

The server image we use is prebuilt by us using the [TLS-Docker-Library](https://github.com/tls-attacker/tls-docker-library).  
We have included certificates in the container, so you do not need to generate them yourself.

:::

For better compatibility, we create a dedicated Docker network that allows TLS-Anvil and the OpenSSL server container to communicate.

```bash
docker network create tls-anvil
```

### Starting the OpenSSL Server

:::info

As mentioned before, we use OpenSSL as an example. In this case, the server uses an RSA certificate. However, TLS-Anvil supports any certificate type and automatically adapts the tests accordingly.

:::

Start the server with the following command. This will download a pre-built image from our GitHub registry and run it.

```bash showLineNumbers
docker run \
    -d \
    --rm \
    --name openssl-server \
    --network tls-anvil \
    ghcr.io/tls-attacker/openssl-server:1.1.1i \
    -port 8443 \
    -cert /certs/rsa2048cert.pem \
    -key /certs/rsa2048key.pem
```

* Lines 2-5: Docker-related command flags
* Line 6: Specifies the Docker image from the TLS-Docker-Library
* Lines 7-9: Flags passed to the OpenSSL `s_server` binary

### Starting TLS-Anvil

Next, start TLS-Anvil. The current directory is mounted into the Docker container to store the results. We connect to the server using its Docker hostname `openssl-server`, which works because both containers are on the same Docker network.

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

* Lines 2-5: Docker-related command flags
* Line 6: Mounts the output directory as a Docker volume
* Line 7: Specifies the TLS-Anvil Docker image
* Line 8: Compresses the results into a zip archive for easier import into Anvil-Web later
* Line 9: Since the OpenSSL example server is single-threaded, only one handshake is performed sequentially
* Line 10: The server runs locally, so the connection timeout is set to 200 ms
* Line 11: Sets the strength parameter, i.e., the `t` value for t-way combinatorial testing
* Line 13: Specifies that we want to test a server
* Line 14: Details how TLS-Anvil should connect to the server

### What Now?

After the test suite finishes, you should see a folder named `Results_...` containing all the results.  
To analyze them, refer to [Viewing Results](Anvil-Web).
