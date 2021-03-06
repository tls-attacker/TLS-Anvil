# Development Environment Setup

First our repository needs to be cloned. Since TLS-Anvil depends on specific TLS-Attacker and TLS-Scanner versions, those are included as submodules.
```
git clone --recurse-submodules git://github.com/tls-attacker/TLS-Anvil
```


## Compile From Terminal
Next we need to compile TLS-Attacker and TLS-Scanner to be able to use TLS-Anvil.
```bash
cd Dependencies/TLS-Attacker-Development
mvn install -DskipTests
cd ../TLS-Scanner-Development
mvn install -DskipTests

cd ../../TLS-Test-Framework
mvn install -DskipTests
```

After that the tests should compile as well.
```bash
cd TLS-Testsuite
mvn package -DskipTests
```

TLS-Anvil can be started by executing the jar file.
```bash
cd TLS-Testsuite/apps
java -jar TLS-Anvil.jar
```

## Setup IDE

TLS-Anvil was mainly developed in IntelliJ IDEA and Netbeans. Since IDEA offers a deeper JUnit integration, the following section explain a basic IDEA setup.

### IDEA

1. Open the TLS-Testsuite Project (`pom.xml`) in IntelliJ
1. Open the `Project Structure` -> `Module` Menu.
1. Add the `TLS-Test-Framework` (`TLS-Test-Framework/pom.xml`) as new Module
1. If you want or need to modify TLS-Attacker and TLS-Scanner as well:
    1. Add `TLS-Attacker` (`Dependencies/TLS-Attacker/pom.xml`) as new Module
    1. Add `TLS-Scanner` (`Dependencies/TLS-Scanner/pom.xml`) as new Module

The project should compile now.

Since TLS-Anvil uses JUnit as testing framework, a single test can be executed using the IDE. For example, if you open a TLS-Anvil test template inside the `de.rub.nds.tlstest.suite.tests` package, a green play button is visible next to the test function.

![](/test_example.png)

The example from the screenshot is a server test. Therefore, a TLS server needs to be running. However, this is not enough since TLS-Anvil needs to know how to connect to the server. Those option are configured by using the environment variables, that are equivalent to the regular TLS-Anvil CLI options. 

The recommended way is to edit the JUnit 5 template of IDEA.
1. Open the `Edit configurations` from the command pallette
1. On the bottom left select `Edit configuration templates`
1. Select `JUnit`
1. Configure the environment variables
    * Use `COMMAND_SERVER` to specify CLI options for testing a server  
        Simple example: 
        ```
        -networkInterface lo0 -parallelHandshakes 1 -strength 1 server -connect localhost:8443 -doNotSendSNIExtension
        ```
    * Use `COMMAND_CLIENT` to specify CLI options for testing a client  
        Simple example: 
        ```
        -networkInterface lo0 -parallelHandshakes 1 -strength 1 client -port 8443 -triggerScript [path to script]
        ```

When the environment variables are configured, it is possible to run a client or server test by clicking the green play buttons next to a function. The specified variables are used by TLS-Anvil to setup the test backend accordingly.

### Netbeans or other

TLS-Anvil is based on Maven and can be compiled like any other Maven Java project. To only execute specific test templates during the development, the CLI of TLS-Anvil offers two options.
* `-testPackage [package]` runs all tests inside a specific Java package.
* `-tags [tag]` runs only test templates that are annotated with a specific tag. When you develop a new test case, annotate the test function temporarily with `@Tag("tag")` to be able to only run this specific test template.
