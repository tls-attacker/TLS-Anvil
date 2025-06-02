import Definition from '@site/src/components/Definition'

# Architecture

The picture below shows the general architecture of TLS-Anvil including the different phases that are executed during a test execution.
Each of those phases is explained in our USENIX Security Paper in Section 4.1. Please have a look there.

![](/Architecture.png)

### Code related information

TLS-Anvil is written in Java and uses the following libraries.
* [JUnit 5](https://junit.org/junit5) - Testing engine. TLS-Anvil heavily uses the extension system of JUnit.
* [TLS-Attacker](https://github.com/tls-attacker/TLS-Attacker) - TLS Stack.
* [TLS-Scanner](https://github.com/tls-attacker/TLS-Scanner) - TLS-Attacker based scanner, used for feature extraction.
* [coffee4j](https://coffee4j.github.io/) - Combinatorial testing library.

Every <Definition id="test template"/> is a JUnit test function with additional java annotations that define an <Definition id="IPM"/> and most importantly to use the test lifecycle execution of TLS-Anvil that exchanges TLS messages with the SUT.

TLS-Anvil is structured into two java modules.  
* TLS-Testsuite: The main module that contains all the templates that are located inside the `de.rub.nds.tlstest.suite.tests` package. This package contains further packages that divides the tests into `server` and `client` tests or tests that work for `both` peers. Inside those packages are the tests are further divided by RFCs.
* TLS-Test-Framework: This module contains all JUnit extensions and test execution logic.

See the next chapter for an example test template and how new templates can be added.
