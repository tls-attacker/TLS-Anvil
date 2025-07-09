# Config Files

As an alternative to configuring TLS-Anvil via command line parameters, you can use a config file in JSON format.
The config file has to either contain a `serverConfig` or `clientConfig` section.

Example config file `myConfig.json` for a server scan:
``` json showLineNumbers
{
  "anvilTestConfig" : {
    "identifier" : "example_server_test",
    "expectedResults" : "expected_results.json",
    "profiles" : [ "example_profile" ],
    "profileFolder" : "./profiles",
    "ignoreCache" : false,
    "parallelTests" : 7,
    "strength" : 2,
    "connectionTimeout" : 200,
    "disableTcpDump" : false,
    "doZip" : true
  },
  "serverConfig" : {
    "host" : "localhost:8443",
    "doNotSendSNIExtension" : false
  },
  "exportTraces" : false,
  "parallelHandshakes" : 5
}
```
All possible config options can be seen in the folder [config_examples](https://github.com/tls-attacker/TLS-Anvil/tree/main/config_examples).

We can use the config file by invoking TLS-Anvil with the ```-tlsAnvilConfig``` parameter.
``` bash showLineNumbers
docker run \
    --rm \
    -it \
    --name tls-anvil \
    --network tls-anvil \
    -v $(pwd):/output/ \
    -v ./myConfig.json:/myConfig.json \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -tlsAnvilConfig /myConfig.json        
```