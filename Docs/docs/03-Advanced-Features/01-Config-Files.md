# Config Files

As an alternative to using command-line arguments, TLS-Anvil supports JSON-based configuration files. These config files must include either a `serverConfig` or `clientConfig` section, depending on the intended scan target.

---

## Example: Server Scan Configuration

Below is a sample `myConfig.json` file for scanning a server:

``` json showLineNumbers title="myConfig.json"
{
  "anvilTestConfig": {
    "identifier": "example_server_test",
    "expectedResults": "expected_results.json",
    "profiles": ["example_profile"],
    "profileFolder": "./profiles",
    "ignoreCache": false,
    "parallelTests": 7,
    "strength": 2,
    "connectionTimeout": 200,
    "disableTcpDump": false,
    "doZip": true
  },
  "serverConfig": {
    "host": "localhost:8443",
    "doNotSendSNIExtension": false
  },
  "exportTraces": false,
  "parallelHandshakes": 5
}
```

A full list of configuration examples is available in the [`config_examples` folder](https://github.com/tls-attacker/TLS-Anvil/tree/main/config_examples) of the TLS-Anvil repository.

---

## Running TLS-Anvil with a Config File

You can run TLS-Anvil using your JSON configuration file by passing it via the `-tlsAnvilConfig` parameter.

```bash showLineNumbers title="Run TLS-Anvil with a Config File"
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

This setup mounts the config file into the container and executes the scan based on the provided configuration.

---
