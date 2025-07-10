import Definition from '@site/src/components/Definition'

# Architecture

The diagram below illustrates the general architecture of TLS-Anvil, highlighting the different phases executed during a test run.  
These phases are explained in detail in our [USENIX Security Paper, Section 4.1](/TLS-Anvil-Paper.pdf).

![TLS-Anvil Architecture](/Architecture.png)

---

### Code-related Information

TLS-Anvil is implemented in **Java** and leverages several key libraries:

- [JUnit 5](https://junit.org/) – Testing engine. TLS-Anvil extensively uses JUnit's extension system.
- [TLS-Attacker](https://github.com/tls-attacker/TLS-Attacker) – Core TLS stack.
- [TLS-Scanner](https://github.com/tls-attacker/TLS-Scanner) – Scanner based on TLS-Attacker, used for feature extraction.
- [coffee4j](https://coffee4j.github.io/) – Library for combinatorial testing.

---

### Key Concepts

Every <Definition id="test template" /> represents a JUnit test function augmented with Java annotations that define an <Definition id="IPM" />.  
Most importantly, these annotations enable the TLS-Anvil test lifecycle, which manages TLS message exchanges with the System Under Test (SUT).

---

### TLS-Anvil Modules

TLS-Anvil is organized into two Java modules:

- **TLS-Testsuite:**  
  The main module containing all test templates.  
  These templates reside in the `de.rub.nds.tlstest.suite.tests` package, further subdivided into:
    - `server` tests
    - `client` tests
    - Tests applicable to `both` peers  
      Inside these, tests are organized by relevant RFCs.

- **TLS-Test-Framework:**  
  This module contains all JUnit extensions and the core test execution logic.

---

See the next chapter for an example test template and instructions on adding new templates.
