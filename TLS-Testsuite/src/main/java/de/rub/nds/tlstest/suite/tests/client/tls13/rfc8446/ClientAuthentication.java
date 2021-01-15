/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8446, section = "4.4.2. Certificate")
public class ClientAuthentication extends Tls13Test {

    @TlsTest(description = "If the server requests client authentication but no " +
            "suitable certificate is available, the client MUST send a " +
            "Certificate message containing no certificates.")
    @Interoperability(SeverityLevel.HIGH)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.MEDIUM)
    public void clientSendsCertificateMessage(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setClientAuthentication(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
}
