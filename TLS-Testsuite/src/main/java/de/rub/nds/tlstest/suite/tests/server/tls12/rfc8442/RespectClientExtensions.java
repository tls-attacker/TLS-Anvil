/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc8442;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;

@ServerTest
public class RespectClientExtensions extends Tls12Test {

    @RFC(number = 8422, section = "5.1. Client Hello Extensions")
    @TlsTest(description = "A server that receives a ClientHello containing one or both of these "
            + "extensions MUST use the client's enumerated capabilities to guide its "
            + "selection of an appropriate cipher suite.  One of the proposed ECC "
            + "cipher suites must be negotiated only if the server can successfully "
            + "complete the handshake while using the curves and point formats "
            + "supported by the client (cf. Sections 5.3 and 5.4).")
    @KeyExchange(supported = KeyExchangeType.ECDH, requiresServerKeyExchMsg = true)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void respectChosenCurve(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);
        constructTest(runner, c);

    }

    @RFC(number = 8422, section = "5.1. Client Hello Extensions")
    @TlsTest(description = "A server that receives a ClientHello containing one or both of these "
            + "extensions MUST use the client's enumerated capabilities to guide its "
            + "selection of an appropriate cipher suite.  One of the proposed ECC "
            + "cipher suites must be negotiated only if the server can successfully "
            + "complete the handshake while using the curves and point formats "
            + "supported by the client (cf. Sections 5.3 and 5.4).")
    @KeyExchange(supported = KeyExchangeType.ECDH, requiresServerKeyExchMsg = true)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void respectChosenCurveWithoutFormats(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(false);
        constructTest(runner, c);

    }

    @Test
    @TestDescription("If the client has used a "
            + "Supported Elliptic Curves Extension, the public key in the server’s "
            + "certificate MUST respect the client’s choice of elliptic curves")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void respectsChosenCurveForCertificates() {
        assertTrue("The server does not respect the client's supported curves when selecting the certificate", TestContext.getInstance().getSiteReport().getResult(AnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY) != TestResult.TRUE);
    }

    private void constructTest(WorkflowRunner runner, Config c) {
        ClientHelloMessage chm = new ClientHelloMessage(c);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            WorkflowTrace trace = i.getWorkflowTrace();
            ECDHEServerKeyExchangeMessage message = trace.getFirstReceivedMessage(ECDHEServerKeyExchangeMessage.class);
            assertNotNull(AssertMsgs.ServerKxNotReceived, message);

            ClientHelloMessage sentChm = trace.getFirstSendMessage(ClientHelloMessage.class);
            byte[] allSentCurves = sentChm.getExtension(EllipticCurvesExtensionMessage.class).getSupportedGroups().getValue();
            byte[] sentEllipticCurve = Arrays.copyOfRange(allSentCurves, 0, 2);
            byte[] receivedEllipticCurve = message.getNamedGroup().getValue();
            assertArrayEquals("Unexpected named group", sentEllipticCurve, receivedEllipticCurve);
        });
    }
}
