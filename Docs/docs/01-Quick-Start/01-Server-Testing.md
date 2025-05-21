# Server Testing

This site demonstrates how to test the OpenSSL server provided by the TLS-Docker-Library.
Testing the server in the most simple form roughly takes around 10 minutes. However, this duration can increase to several depending on the strength parameter that that basically defines how often a single test case triggered with different parameters.

### Preparations

The server we will use, is found in the [TLS-Docker-Library](https://github.com/tls-attacker/tls-docker-library).

Before the server is able to do anything we need to generate a TLS certificate. Inside the TLS-Docker-Library repo, run:

```bash
./setup.sh
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
    --name tls-anvil \
    --network tls-anvil \
    -v $(pwd):/output/ \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -parallelTestCases 1 \
    -connectionTimeout 200 \
    -strength 1 \
    -identifier openssl-server \
    server \
    -connect openssl-server:8443
```

* Lines 2-5: Docker related command flags
* Line 6: Set the output directory through a docker volume
* Line 7: Specifies the TLS-Anvil docker image
* Line 8: Since the OpenSSL example server is single threaded, we can only perform one handshakes sequentially
* Line 9: We run our server locally, so we can reduce the timeout to 200ms.
* Line 10: Defines the strength, i.e. the `t` for t-way combinatorial testing
* Line 12: We want to test a server
* Line 13: Determines the details how TLS-Anvil should connect to the server

### Config Files

As an alternative to passing specific  parameters via the command line, we can define a config file using json.
Example config file ```myConfig.json```:
```
{
    "anvilTestConfig" : {
      "tags" : [ ],
      "testPackage" : null,
      "ignoreCache" : true,
      "outputFolder" : "/path_to_outputFolder",
      "parallelTestCases" : 1,
      "parallelTests" : null,
      "restartServerAfter" : 0,
      "timeoutActionCommand" : [ ],
      "identifier" : null,
      "strength" : 1,
      "connectionTimeout" : 300,
      "prettyPrintJSON" : false,
      "networkInterface" : "any",
      "disableTcpDump" : false,
      "endpointMode" : null
    },
    "serverConfig" : {
      "host" : "openssl-server:8443",
  
      "sniHostname" : null,
      "doNotSendSNIExtension" : true
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
    -tlsAnvilConfig /anvil_configs/myConfig.json        
```

### Profiles
To run specific tests, you can define custom profiles in JSON format.
Example file happyFlow.json:
```
{
 "name" : "happyFlow",
 "profiles" : [],
 "testIds" : [
   "5246-jsdAL1vDy5",
   "8446-jVohiUKi4u"
 ]
}
```
* Line 2: Name of the profile
* Line 3: An array referencing other profiles. All tests defined in  these other profiles will be included in testruns of the current profile. (Empty in this example)
* Line 4-6: List of specific test IDs to run (HappyFlow for TLS 1.2 and TLS 1.3 in this example)

To use the profile, run TLS-Anvil with the ```profiles``` and ```profileFolder``` parameters.

```
docker run \
    --rm \
    -it \
    --name tls-anvil \
    --network tls-anvil \
    -v $(pwd):/output/ \
    -v /path_to_folder_containing_hapyflow_json_file/:/profiles \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -parallelTestCases 1 \
    -connectionTimeout 200 \
    -strength 1 \
    -identifier openssl-server \
    -profileFolder /profiles \
    -profiles happyFlow \
    server \
    -connect openssl-server:8443
```
