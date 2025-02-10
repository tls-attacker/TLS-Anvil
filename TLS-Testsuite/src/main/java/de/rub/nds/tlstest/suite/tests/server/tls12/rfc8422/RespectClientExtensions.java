/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc8422;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.Arrays;

@ServerTest
public class RespectClientExtensions extends Tls12Test {

    @AnvilTest(id = "8422-zuAGxqyDEg")
    @KeyExchange(supported = KeyExchangeType.ECDH, requiresServerKeyExchMsg = true)
    public void respectChosenCurve(WorkflowRunner runner, AnvilTestCase testCase) {
        Config c = getPreparedConfig(runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);
        constructTest(runner, c, testCase);
    }

    @AnvilTest(id = "8422-bc43G6qpcS")
    @KeyExchange(supported = KeyExchangeType.ECDH, requiresServerKeyExchMsg = true)
    public void respectChosenCurveWithoutFormats(WorkflowRunner runner, AnvilTestCase testCase) {
        Config c = getPreparedConfig(runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(false);
        constructTest(runner, c, testCase);
    }

    @NonCombinatorialAnvilTest(id = "8422-xyn7SDVFRX")
    public void respectsChosenCurveForCertificates() {
        assertTrue(
                TestContext.getInstance()
                                .getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY)
                        != TestResults.TRUE,
                "The server does not respect the client's supported curves when selecting the certificate");
    }

    private void constructTest(WorkflowRunner runner, Config config, AnvilTestCase testCase) {
        ClientHelloMessage chm = new ClientHelloMessage(config);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm), new ReceiveTillAction(new ServerHelloDoneMessage()));

        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);

        WorkflowTrace trace = state.getWorkflowTrace();
        ECDHEServerKeyExchangeMessage message =
                trace.getFirstReceivedMessage(ECDHEServerKeyExchangeMessage.class);
        assertNotNull(message, AssertMsgs.SERVER_KEY_EXCHANGE_NOT_RECEIVED);

        ClientHelloMessage sentChm = workflowTrace.getFirstSentMessage(ClientHelloMessage.class);
        byte[] allSentCurves =
                sentChm.getExtension(EllipticCurvesExtensionMessage.class)
                        .getSupportedGroups()
                        .getValue();
        byte[] sentEllipticCurve = Arrays.copyOfRange(allSentCurves, 0, 2);
        byte[] receivedEllipticCurve = message.getNamedGroup().getValue();
        assertArrayEquals(sentEllipticCurve, receivedEllipticCurve, "Unexpected named group");
    }
}
