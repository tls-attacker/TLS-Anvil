/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc8422;

import static org.junit.Assert.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class RespectClientExtensions extends Tls12Test {

    @AnvilTest
    @KeyExchange(supported = KeyExchangeType.ECDH, requiresServerKeyExchMsg = true)
    public void respectChosenCurve(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);
        constructTest(runner, c);
    }

    @AnvilTest
    @KeyExchange(supported = KeyExchangeType.ECDH, requiresServerKeyExchMsg = true)
    public void respectChosenCurveWithoutFormats(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(false);
        constructTest(runner, c);
    }

    @Test
    public void respectsChosenCurveForCertificates() {
        assertTrue(
                "The server does not respect the client's supported curves when selecting the certificate",
                TestContext.getInstance()
                                .getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY)
                        != TestResults.TRUE);
    }

    private void constructTest(WorkflowRunner runner, Config c) {
        ClientHelloMessage chm = new ClientHelloMessage(c);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm), new ReceiveTillAction(new ServerHelloDoneMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);

                            WorkflowTrace trace = i.getWorkflowTrace();
                            ECDHEServerKeyExchangeMessage message =
                                    trace.getFirstReceivedMessage(
                                            ECDHEServerKeyExchangeMessage.class);
                            assertNotNull(AssertMsgs.SERVER_KEY_EXCHANGE_NOT_RECEIVED, message);

                            ClientHelloMessage sentChm =
                                    trace.getFirstSendMessage(ClientHelloMessage.class);
                            byte[] allSentCurves =
                                    sentChm.getExtension(EllipticCurvesExtensionMessage.class)
                                            .getSupportedGroups()
                                            .getValue();
                            byte[] sentEllipticCurve = Arrays.copyOfRange(allSentCurves, 0, 2);
                            byte[] receivedEllipticCurve = message.getNamedGroup().getValue();
                            assertArrayEquals(
                                    "Unexpected named group",
                                    sentEllipticCurve,
                                    receivedEllipticCurve);
                        });
    }
}
