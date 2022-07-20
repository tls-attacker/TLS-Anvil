import Definition from '@site/src/components/Definition'

# Potential Problems

### TLS-Anvil does not execute any tests
You probably want to test a client or server that violates some of the specifications. In this case the feature discovery of the <Definition id="SUT" /> probably fails. The feature discovery is executed first and is used by TLS-Anvil to determine which TLS specific parameters and algorithms the SUT supports to be able to configure the test suite automatically. If this discovery fails, TLS-Anvil thinks the SUT does not support any parameters and therefore does not execute any <Definition id="test templates" />. 

To fix this problem, the feature discovery must be fixed. For server tests this is handled by [TLS-Scanner](https://github.com/tls-attacker/TLS-Scanner). For client tests this is performed inside the `clientTestPreparation` function of the `de.rub.nds.tlstest.framework.execution.TestRunner` class.