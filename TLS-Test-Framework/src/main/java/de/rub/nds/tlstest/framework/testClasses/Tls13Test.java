/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.testClasses;


import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@TlsVersion(supported = ProtocolVersion.TLS13)
@KeyExchange(supported = KeyExchangeType.ALL13)
@Tag("tls13")
public class Tls13Test extends TlsBaseTest {
    @Override
    public Config getConfig() {
        return context.getConfig().createTls13Config();
    }

    @Override
    public Config getPreparedConfig(ArgumentsAccessor argAccessor, WorkflowRunner runner) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
