# Configuration Options Extension

When the configuration options extension is loaded, configuration options (COs) are included in the input parameter model. That can be done using the following example commands:

```console
java -jar <...>/TLS-Testsuite.jar \
 -configOptionsConfigFile <...>/TestFramework/examples/exampleConfig.xml \
 -parallelHandshakes 1 \
 -strength 2 \
 server -connect localhost:4433
```

This command starts server tests with COs. The library to test and the tested COs are specified within the given configuration options config file (exampleConfig.xml in this case). To see how this file works, check out the [example config file](../../../../../../../../../../examples/exampleConfig.xml).

In this example, we test OpenSSL's s_server program. Since it only allows for one simultaneous connection, we must set `-parallelHandshakes` to 1 (this is not necessary for client tests). Additionally, the Testsuite command expects the server destination. Since we use multiple destinations for multiple CO combinations, we only need to insert a dummy address (alternatively, we can update the cli parsing logic in the future).

The analog command for client testing is the following:

```console
java -jar <...>/TLS-Testsuite.jar \
 -configOptionsConfigFile <...>/TestFramework/examples/exampleConfig.xml \
 -strength 2 \
 client -port 4433
```

For clients, the port is a dummy value.

## Preparations

To use the extension, the following preparations must be applied:
-   The TLS-Docker-Library path must be specified within the CO config file. The docker library's `setup.sh` script must have been executed so that all necessary docker base images and the docker volume `certs` exist. The docker library's version must contain the directory `./images/openssl/configurationOptionsFactoryWithCoverage`; otherwise, a newer version must be used.
-   When running the extension, make sure that docker is running.

## Troubleshooting

- **The client tests won't continue in the preparation phase:** Make sure the CO config field `dockerClientDestinationHost` is set to the correct value. The client within the docker container must be able to find the Testsuite's servers.
- **Many tests fail on your system due to a timeout:** The timeout must be increased using the `-connectionTimeout` cli option.
- **The test execution dies at some point due to missing memory:** You may have to decrease the number of simultaneously running containers using the `maxRunningContainers` field in the CO config.
- **The test execution dies at the very end after the test result summary is printed out due to missing memory:** You may have to decrease the number of simultaneous container shutdowns using the `maxRunningContainerShutdowns` field in the CO config. Shutting down containers is much more resource heavy than simply running them since the code coverage data is collected at this point.

## Analyze Configuration Options Related Data

Within the test output directory (default: `TestSuiteResults_Timestamp`), the CO extension creates a folder `ConfigOptionsResults` containing additional data and information regarding the created and used builds. The following directories and files are created:

- `buildsOverview.csv:` Contains the docker tags for all builds, the COs used to create them, and the build time.
- `buildsAccesses.csv:` Contains how often each build (identified by docker tag) is used.
- `BuildLog`: Contains the docker container logs for the build containers. They can be used for debugging purposes.
- `ContainerLog`: Contains the logs for the docker containers running the TLS server/client. They can be used for debugging purposes. Note that it only logs until the first shutdown (it seems that docker does not continue logging after the container restarts).

The coverage data is stored within the docker volume named `coverage`. If you are interested in the coverage data, you want to extract the data from this volume. To create an overview of the coverage data and to obtain the merged coverage report, the python program `TLS-Test-Framework/TestFramework/tools/coverageMerger.py` is used. This program creates the file `coverage_overview.csv` containing the collected coverage data.

For deeper analysis, you may want to collect the information of all individual `.csv` files in one single file. This can be achieved by calling the `TLS-Test-Framework/TestFramework/tools/collectResults.py` python program. It collects the three `.csv` files in one well-formatted excel document.

