/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.1.1 Cryptographic Negotiation")
public class CryptographicNegotiation extends Tls13Test {

    @TlsTest(description = "If the server is unable to negotiate a supported set of parameters " +
            "(i.e., there is no overlap between the client and server parameters), it MUST abort " +
            "the handshake with either a \"handshake_failure\" or \"insufficient_security\" fatal alert (see Section 6).")
    @Interoperability(SeverityLevel.MEDIUM)
    public void noOverlappingParameters(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage chm = new ClientHelloMessage(config);
        //TODO: should we use actually unsupported groups here (if there are any)?
        //using a GREASE group does not seem to be what the RFC means here
        chm.getExtension(KeyShareExtensionMessage.class).getKeyShareList().get(0).setGroupConfig(NamedGroup.GREASE_00);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(chm),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = trace.getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }

            AlertDescription description = AlertDescription.getAlertDescription(alert.getDescription().getValue());
            assertTrue(
                    AssertMsgs.UnexpectedAlertDescription,
                    description == AlertDescription.HANDSHAKE_FAILURE || description == AlertDescription.INSUFFICIENT_SECURITY
            );
        });
    }


}
