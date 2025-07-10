# Development Environment Setup

First, clone our repository:

```bash
git clone git://github.com/tls-attacker/TLS-Anvil
```

## Compile From Terminal

TLS-Anvil depends on specific versions of TLS-Attacker, TLS-Scanner, and Anvil-Core as its testing framework. These are managed as Maven dependencies and will be automatically fetched during the build process.

```bash
mvn clean install -DskipTests
```

TLS-Anvil can be started by executing the JAR file:

```bash
cd apps
java -jar TLS-Anvil.jar
```

## Setup IDE

TLS-Anvil was primarily developed using IntelliJ IDEA and NetBeans. Since IntelliJ IDEA offers more advanced JUnit integration, the following section describes a basic setup for IDEA.

### IntelliJ IDEA

1. Open the TLS-Testsuite project by selecting the root `pom.xml` file in IntelliJ IDEA.
2. If you intend to modify TLS-Attacker and TLS-Scanner as well (which are maintained in separate Git repositories):
    1. Add `TLS-Attacker` (`TLS-Attacker/pom.xml`) as a new module.
    2. Add `TLS-Scanner` (`TLS-Scanner/pom.xml`) as a new module.

At this point, the project should compile successfully.

Since TLS-Anvil uses JUnit as its testing framework, individual tests can be executed directly from the IDE. For example, when opening a TLS-Anvil test template located in the `de.rub.nds.tlstest.suite.tests` package, a green play button will appear next to each test method.

![](/test_example.png)

The example in the screenshot is a server test, so a TLS server must be running. Additionally, TLS-Anvil requires connection details to the server. These options are configured via environment variables, which correspond to the regular TLS-Anvil CLI options.

The recommended approach is to edit the JUnit 5 run configuration template in IntelliJ IDEA:

1. Open `Edit Configurations` from the command palette.
2. In the bottom left, select `Edit Configuration Templates`.
3. Select the `JUnit` template.
4. Configure the environment variables:
    * Use `COMMAND_SERVER` to specify CLI options for testing a server.  
      Example:

```
-networkInterface lo0 -parallelHandshakes 1 -strength 1 server -connect localhost:8443 -doNotSendSNIExtension
```

    * Use `COMMAND_CLIENT` to specify CLI options for testing a client.  
      Example:

```
-networkInterface lo0 -parallelHandshakes 1 -strength 1 client -port 8443 -triggerScript [path to script]
```

Once the environment variables are configured, you can run client or server tests by clicking the green play buttons next to the test methods. TLS-Anvil will use these variables to configure the test backend accordingly.

### NetBeans or Other IDEs

TLS-Anvil is a Maven-based project and can be built like any other Maven Java project. To execute specific test templates during development, the TLS-Anvil CLI provides two options:

* `-testPackage [package]` — Runs all tests within the specified Java package.
* `-tags [tag]` — Runs only test templates annotated with the specified tag. When developing a new test case, temporarily annotate the test method with `@Tag("tag")` to run only that specific test template.
