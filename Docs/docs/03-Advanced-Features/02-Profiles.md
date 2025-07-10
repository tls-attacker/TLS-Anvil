# Profiles

TLS-Anvil supports test selection through **profiles**, which allow you to restrict and organize the tests to be executed.

Profiles are defined in **JSON format** and specify:
- A **profile name**
- Optional **references to sub-profiles**
- A list of **test IDs** to include in the test run

Test IDs can be found in the [`metadata.json`](https://github.com/tls-attacker/TLS-Anvil/blob/main/TLS-Testsuite/src/main/resources/metadata.json) file.

---

## Example Profile: `happyFlow.json`

```json showLineNumbers title="happyFlow.json"
{
  "name": "happyFlow",
  "profiles": [],
  "testIds": [
    "5246-jsdAL1vDy5",
    "8446-jVohiUKi4u"
  ]
}
```

* Line 2:  The name of the profile
* Line 3: A list of referenced sub-profiles (empty in this example) |
* Line 4-6: The test IDs to execute (representing tests for TLS 1.2 and TLS 1.3 happy paths) |

---

## Using a Profile with TLS-Anvil

To use a profile, pass the `-profiles` and `-profileFolder` parameters. The `.json` extension is optional.

```bash showLineNumbers title="Run with Profile"
docker run \
    --rm \
    -it \
    --name tls-anvil \
    --network tls-anvil \
    -v $(pwd):/output/ \
    -v ./profiles/:/profiles/ \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -parallelHandshakes 1 \
    -connectionTimeout 200 \
    -strength 1 \
    -identifier openssl-server \
    -profileFolder /profiles \
    -profiles happyFlow \
    server \
    -connect openssl-server:8443
```

This command:
- Mounts the `profiles` directory
- Selects the `happyFlow` profile
- Connects to the target TLS server at `openssl-server:8443`

---

You can chain multiple profiles or build complex configurations by referencing other profiles inside the `profiles` array. This supports modular and scalable test setups.
