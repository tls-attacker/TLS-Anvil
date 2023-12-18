import JavaClass from "@site/src/components/JavaClass"
import Definition from "@site/src/components/Definition"

# Base IPMs

TLS-Anvil provides 4 common IPM that specify which parameters are used as input for the combinatorial testing algorithm. The values are determined automatically based on the features the <Definition id="SUT" /> supports and the constraints that are applied to restrict the parameter values.

The models are specified inside the <JavaClass path="TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/anvil/TlsModelTypes.java"/> enum. Which one is used is specified by annotating a test template with the `@ModelFromScope` annotation.

By default the `GENERIC` model is used, since the `@ModelFromScope` annotation is part of the <JavaClass path="TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/testClasses/TlsBaseTest.java"/> base class.

In the following, the 4 base models are listed with their corresponding parameters.
* `EMPTY`
    * No parameters
* `GENERIC`
    * `CIPHERSUITE` (<a href="https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/constants/CipherSuite.java">CipherSuite</a> enum)
    * `NAMED_GROUP` (<a href="https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/constants/NamedGroup.java">NamedGroup</a> enum)
    * `RECORD_LENGTH` (Integer)
    * `TCP_FRAGMENTATION` (Boolean)
    * `INCLUDE_CHANGE_CIPHER_SPEC` (Boolean) (TLS 1.3 only)
    * Server tests:
    * `INCLUDE_ALPN_EXTENSION` (Boolean)
    * `INCLUDE_HEARTBEAT_EXTENSION` (Boolean)
    * `INCLUDE_PADDING_EXTENSION` (Boolean)
    * `INCLUDE_RENEGOTIATION_EXTENSION` (Boolean)
    * `INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION` (Boolean)
    * `INCLUDE_SESSION_TICKET_EXTENSION` (Boolean)
    * `MAX_FRAGMENT_LENGTH` (<a href="https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/constants/MaxFragmentLength.java">MaxFragmentLength</a> enum)
    * `INCLUDE_ENCRYPT_THEN_MAC_EXTENSION` (Boolean)
    * `INCLUDE_PSK_EXCHANGE_MODES_EXTENSION` (Boolean, TLS 1.3 only)
    * `INCLUDE_GREASE_CIPHER_SUITES` (Boolean)
    * `INCLUDE_GREASE_NAMED_GROUPS` (Boolean)
    * `INCLUDE_GREASE_SIG_HASH_ALGORITHMS` (Boolean)
    * Client tests:
    * `INCLUDE_ENCRYPT_THEN_MAC_EXTENSION` (Boolean)
    * `INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION` (Boolean)
* `CERTIFICATE`
    * Same as generic
    * Client tests:
    * `CERTIFICATE` (Certificates with different keys)
    * `SIG_HASH_ALGORITHM` (<a href="https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/constants/SignatureAndHashAlgorithm.java">SignatureAndHashAlgorithm</a> enum)
* `LENGTHFIELD`
    * Same as `CERTIFICATE`

Beside those parameters many more are available that are specified inside the <JavaClass path="TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/model/TlsParameterType.java" /> enum.

For each parameter a separate class exists inside the <JavaClass path="TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/model/derivationParameter"/> package that defines how the parameter value is applied to the TLS-Attacker configuration.

How additional parameters and/or parameter values are used, is described on the next page.
