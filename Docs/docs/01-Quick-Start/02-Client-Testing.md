# Client Testing

This page demonstrates how to test the OpenSSL client using the TLS-Docker-Library.  
You can also test other implementations—for example, by [using the TLS-Docker-Library](/docs/Docker-Library) or by running your own client binary.

Running the test suite in its simplest form typically takes around 15 minutes.  
However, the duration may increase depending on the `strength` parameter, which defines how many variations of a single test case are executed with different parameters.

### Preparations

Just like with server testing, we first create a dedicated Docker network that allows the TLS-Anvil and OpenSSL client containers to communicate.  
If the network has already been created, you can skip this step.

```bash
docker network create tls-anvil
```

### Starting the TLS-Anvil Container

Since the client needs to connect to TLS-Anvil, the test suite container must be started first.  
Once running, the test suite will wait for the client to connect, so keep the terminal open.

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

* Lines 2–5: Docker-related command flags
* Line 6: Mounts the current directory as the output directory
* Line 7: Specifies the TLS-Anvil Docker image
* Line 8: Compresses the results into a ZIP file for easier import into Anvil-Web
* Lines 9–10: TLS-Anvil can run multiple tests and handshakes in parallel since the client can be started multiple times
* Line 11: Sets the `strength` parameter for t-way combinatorial testing
* Line 12: Defines an identifier name that appears in the test report
* Line 13: Indicates that we are testing a client
* Line 14: Specifies the port TLS-Anvil listens on for client connections
* Line 15: Provides a script that is executed before each handshake to trigger a new client connection. See explanation below.

:::tip

If you want the trigger script to execute on your host machine, we recommend to run the `TLS-Anvil.jar` executable directly on your host machine using Java 21 or newer. The jar files can be found under [Releases](https://github.com/tls-attacker/TLS-Anvil/releases).

:::

### Starting the OpenSSL Client Container

:::info

As mentioned, we use OpenSSL as an example client.  
The OpenSSL client image used here is pre-built using the [TLS-Docker-Library](https://github.com/tls-attacker/tls-docker-library).  
Its entrypoint is a small HTTP server that exposes two REST API endpoints on port 8090:

- `GET /trigger` — starts the client
- `GET /shutdown` — shuts down the HTTP server and terminates the container

:::

Start the client using the following command. This downloads a pre-built image from our GitHub Container Registry and runs it.  
Since TLS-Anvil is already running, open a new terminal to start the client.

```bash showLineNumbers
docker run \
    -d \
    --rm \
    --name openssl-client \
    --network tls-anvil \
    ghcr.io/tls-attacker/openssl-client:1.1.1i \
    -connect tls-anvil:8443
```

* Lines 2–5: Docker-related command flags
* Line 6: Specifies the OpenSSL client image from the TLS-Docker-Library
* Line 7: This argument is passed to the OpenSSL `s_client` binary, which is executed each time a `GET /trigger` request is sent to port 8090

:::note

Note, that if you are using a platform beyond linux/amd64 (e.g., on a **Macbook**), you might need to use the parameter `--platform linux/amd64` to correctly start the image.

:::

### What Now?

After the test suite finishes, a folder named `Results_...` will appear in your working directory.  
This folder contains all the test results. To analyze them, proceed to the next page.
