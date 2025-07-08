# Profiles
TLS-Anvil has the option to restrict the tests being run using profiles.
To select only specific tests to run, you can define custom profiles in JSON format.
The profile has to have a name, can contain a reference to sub profiles and a list of test ids.
The test ids can be found in the [metadata.json](https://github.com/tls-attacker/TLS-Anvil/blob/main/TLS-Testsuite/src/main/resources/metadata.json) file

Example file `happyFlow.json`:
``` json showLineNumbers
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

To use the profile, run TLS-Anvil with the `profiles` and `profileFolder` parameters. You can omit the *.json* extension.

``` bash showLineNumbers
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