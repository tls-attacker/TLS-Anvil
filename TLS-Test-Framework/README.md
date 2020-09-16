# TLS-Test-Framework

The TLS-Test-Framework powers the [TLS-Testsuite](https://github.com/RUB-NDS/TLS-Testsuite) and was developed as part of the master's thesis *Development and Evaluation of a TLS-Testsuite* at the *Ruhr-University Bochum* in cooperation with the *TÜV Inormationstechnik GmbH*.

The framework provides JUnit extensions, annotations and an API for modeling tests for the TLS protocol. It uses the TLS stack of [TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker) for the execution of handshake workflows that are defined in test cases.


## Connected Projects
* [TLS-Testsuite](https://github.com/RUB-NDS/TLS-Testsuite)
* [TLS-Testsuite-Report-Analyzer](https://github.com/RUB-NDS/TLS-Testsuite-Report-Analyzer)
* [TLS-Testsuite-Large-Scale-Evaluator](https://github.com/RUB-NDS/TLS-Testsuite-Large-Scale-Evaluator)

## Features
* Client and Server testing
* Automated client testing 
    * Provide a shell command that is executed to trigger the client
* Parallel test execution
    * Tests TLS handshakes are executed in parallel
* Conditional test execution based on annotations
* Automatic test derivation
* Test report generation (JSON and XML)
* Command-line interface definition for configuring...
    * ... parallelism
    * ... target
* Complex handshake validation
