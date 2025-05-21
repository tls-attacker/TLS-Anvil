# Client Testing

This site demonstrates how to test the OpenSSL client provided by the TLS-Docker-Library.
Testing the client in the most simple form roughly takes around 15 minutes. However, this duration can increase to several depending on the strength parameter that that basically defines how often a single test case triggered with different parameters.

### Preparations

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
    --network tls-anvil \
    --name tls-anvil \
    -v $(pwd):/output/ \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -parallelTestCases 3 \
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
* Lines 8-9: Since the client can started multiple times, TLS-Anvil can run multiple tests and handshakes in parallel
* Line 10: Defines the strength, i.e. the `t` for t-way combinatorial testing
* Line 11: Defines an arbitrary name that is written to the report
* Line 12: We want to test a client
* Line 13: The port on which TLS-Anvil listens to accept requests from the client
* Line 14: Specifies a script that is executed before each handshake, which the goal to trigger a connection from the client. See below how this works.

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
* Line 6: Specifies the OpenSSL client image from the TLS-Docker-Library
* Line 7: This is passed to the OpenSSL `s_client` binary, which is started each time a HTTP-GET request is sent to `:8090/trigger`.

### Config Files

As an alternative to passing specific parameters via the command line, we can define a config file using the JSON file format.
Example config file ```myConfig.json```:
```
{
  "anvilTestConfig" : {
    "testPackage" : null,
    "ignoreCache" : true,
    "outputFolder" : "/home/david/git/helper_scripts/out_custom_client_s1",
    "parallelTestCases" : 1,
    "parallelTests" : 1,
    "restartServerAfter" : 0,
    "timeoutActionCommand" : [ ],
    "identifier" : "openssl-client",
    "strength" : 1,
    "connectionTimeout" : 200,
    "prettyPrintJSON" : false,
    "networkInterface" : "any",
    "disableTcpDump" : false,
    "endpointMode" : null,
  },

  "clientConfig" : {
    "port" : 8443,
    "triggerScriptCommand" : ["curl","--connect-timeout","2","openssl-client:8090/trigger"]
  },

  "exportTraces" : false
}
```
We can use the config file by invokeing TLS-Anvil with the ```-tlsAnvilConfig``` parameter: 
```
docker run \
    --rm \
    -it \
    --name tls-anvil \
    --network tls-anvil \
    -v $(pwd):/output/ \
    -v /path_to_folder_containing_myConfig_json_file/:/anvil_configs \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -tlsAnvilConfig /anvil_configs/myConfig.json \
```
