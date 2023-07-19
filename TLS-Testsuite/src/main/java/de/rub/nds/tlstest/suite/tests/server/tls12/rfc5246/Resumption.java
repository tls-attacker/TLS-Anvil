/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 5246, section = "F.1.4  Resuming Sessions")
@ServerTest
public class Resumption extends Tls12Test {

    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    public ConditionEvaluationResult supportsResumption() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled(
                    "Does not support ID based session resumption");
        }
    }

    public ConditionEvaluationResult supportsResumptionAndSniActive() {
        if (supportsResumption().isDisabled() || sniActive().isDisabled()) {
            return ConditionEvaluationResult.disabled("SNI disabled or resumption not supported");
        } else {
            return ConditionEvaluationResult.enabled("");
        }
    }

    public ConditionEvaluationResult sniActive() {
        Config c = this.getConfig();
        if (c.isAddServerNameIndicationExtension()) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("SNI is disabled");
    }

    @AnvilTest(
            description =
                    "A server that implements this extension MUST NOT accept the request "
                            + "to resume the session if the server_name extension contains a "
                            + "different name.")
    @RFC(number = 6066, section = "3.  Server Name Indication")
    @MethodCondition(method = "supportsResumptionAndSniActive")
    @SecurityCategory(SeverityLevel.LOW)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.LOW)
    public void rejectSniDisparityResumption(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastMessage(
                        WorkflowTraceType.FULL_RESUMPTION, HandshakeMessageType.SERVER_HELLO);

        ClientHelloMessage cHello = workflowTrace.getLastSendMessage(ClientHelloMessage.class);
        ServerNameIndicationExtensionMessage sni2 =
                cHello.getExtension(ServerNameIndicationExtensionMessage.class);

        ServerNamePair pair =
                new ServerNamePair(
                        c.getSniType().getValue(),
                        ("test" + c.getDefaultClientConnection().getHostname())
                                .getBytes(Charset.forName("ASCII")));
        sni2.setServerNameList(
                new ArrayList<ServerNamePair>() {
                    {
                        add(pair);
                    }
                });

        runner.execute(workflowTrace, c)
                .validateFinal(
                        s -> {
                            WorkflowTrace executedTrace = s.getWorkflowTrace();
                            ServerHelloMessage sHello =
                                    executedTrace.getFirstReceivedMessage(ServerHelloMessage.class);
                            ServerHelloMessage sHello2 =
                                    executedTrace.getLastReceivedMessage(ServerHelloMessage.class);
                            ClientHelloMessage cHello2 =
                                    executedTrace.getLastSendMessage(ClientHelloMessage.class);
                            assertNotNull(AssertMsgs.SERVER_HELLO_NOT_RECEIVED, sHello);

                            // only test if we can assume that the server accepted the SNI in
                            // the initial handshake
                            if (sHello.containsExtension(ExtensionType.SERVER_NAME_INDICATION)
                                    && sHello2 != null
                                    && sHello2 != sHello) {
                                // server hello of resumption MUST NOT not contain this extension
                                assertTrue(
                                        "Server accepted resumption using different SNI",
                                        !Arrays.equals(
                                                cHello2.getSessionId().getValue(),
                                                sHello2.getSessionId().getValue()));
                            }
                        });
    }

    @AnvilTest(
            description =
                    "When resuming a session, the server MUST "
                            + "NOT include a server_name extension in the server hello.")
    @RFC(number = 6066, section = "3.  Server Name Indication")
    @MethodCondition(method = "supportsResumptionAndSniActive")
    @SecurityCategory(SeverityLevel.LOW)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.LOW)
    public void serverHelloSniInResumption(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastMessage(
                        WorkflowTraceType.FULL_RESUMPTION, HandshakeMessageType.SERVER_HELLO);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        s -> {
                            WorkflowTrace trace = s.getWorkflowTrace();
                            ServerHelloMessage sHello =
                                    trace.getFirstReceivedMessage(ServerHelloMessage.class);
                            ServerHelloMessage sHello2 =
                                    trace.getLastReceivedMessage(ServerHelloMessage.class);
                            ClientHelloMessage cHello2 =
                                    trace.getLastSendMessage(ClientHelloMessage.class);
                            assertNotNull(AssertMsgs.SERVER_HELLO_NOT_RECEIVED, sHello);

                            if (sHello2 != null
                                    && Arrays.equals(
                                            cHello2.getSessionId().getValue(),
                                            sHello2.getSessionId().getValue())) {
                                assertFalse(
                                        "Server included SNI extension in resumed session",
                                        sHello2.containsExtension(
                                                ExtensionType.SERVER_NAME_INDICATION));
                            }
                        });
    }

    @AnvilTest(
            description =
                    "In this case, other connections corresponding to the "
                            + "session may continue, but the session identifier MUST be invalidated, "
                            + "preventing the failed session from being used to establish new "
                            + "connections. [...]"
                            + "Thus, any connection terminated with a fatal alert MUST NOT be resumed.")
    @RFC(number = 5246, section = "7.2. Alert Protocol and 7.2.2 Error Alerts")
    @MethodCondition(method = "supportsResumption")
    @IncludeParameter("ALERT")
    @ExcludeParameter("INCLUDE_SESSION_TICKET_EXTENSION")
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void rejectResumptionAfterFatalPostHandshake(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastMessage(
                        WorkflowTraceType.FULL_RESUMPTION, HandshakeMessageType.SERVER_HELLO);
        AlertDescription alertDescr =
                parameterCombination.getParameter(AlertDerivation.class).getSelectedValue();

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(alertDescr.getValue()));

        SendAction finSend =
                (SendAction)
                        WorkflowTraceUtil.getFirstSendingActionForMessage(
                                HandshakeMessageType.FINISHED, workflowTrace);
        finSend.getSendMessages().add(alert);
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        s -> {
                            WorkflowTrace trace = s.getWorkflowTrace();
                            ClientHelloMessage resumptionClientHello =
                                    trace.getLastSendMessage(ClientHelloMessage.class);
                            ServerHelloMessage firstServerHello =
                                    trace.getFirstReceivedMessage(ServerHelloMessage.class);
                            ServerHelloMessage secondServerHello =
                                    trace.getLastReceivedMessage(ServerHelloMessage.class);

                            // for ticket-based resumption
                            ChangeCipherSpecMessage firstCcs =
                                    trace.getFirstReceivedMessage(ChangeCipherSpecMessage.class);
                            ChangeCipherSpecMessage secondCcs =
                                    trace.getLastReceivedMessage(ChangeCipherSpecMessage.class);
                            assertTrue(
                                    "Did not receive both expected Server Hello messages",
                                    firstServerHello != null
                                            && secondServerHello != null
                                            && secondServerHello != firstServerHello);
                            if (resumptionClientHello.getSessionIdLength().getValue() > 0) {
                                ServerHelloMessage sHello =
                                        trace.getLastReceivedMessage(ServerHelloMessage.class);
                                assertTrue(
                                        "Server accepted resumption via SessionID after Fatal Alert",
                                        !Arrays.equals(
                                                resumptionClientHello.getSessionId().getValue(),
                                                sHello.getSessionId().getValue()));
                            } else {
                                assertTrue(
                                        "Server accepted resumption via Tickets after Fatal Alert",
                                        secondCcs == null || secondCcs == firstCcs);
                            }
                        });
    }

    @AnvilTest(
            description = "Thus, any connection terminated with a fatal alert MUST NOT be resumed.")
    @RFC(number = 5246, section = "7.2.2 Error Alerts")
    @MethodCondition(method = "supportsResumption")
    @ExcludeParameter("INCLUDE_SESSION_TICKET_EXTENSION")
    @SecurityCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @IncludeParameter("ALERT")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void rejectResumptionAfterInvalidFinished(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastMessage(
                        WorkflowTraceType.FULL_RESUMPTION, HandshakeMessageType.SERVER_HELLO);

        FinishedMessage fin =
                (FinishedMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.FINISHED, workflowTrace);
        fin.setVerifyData(Modifiable.xor(new byte[] {0x01}, 0));
        workflowTrace.addTlsAction(new ReceiveAction());

        runner.execute(workflowTrace, c)
                .validateFinal(
                        s -> {
                            WorkflowTrace trace = s.getWorkflowTrace();
                            ClientHelloMessage cHello =
                                    trace.getLastSendMessage(ClientHelloMessage.class);
                            if (WorkflowTraceUtil.didReceiveMessage(
                                            HandshakeMessageType.SERVER_HELLO, trace)
                                    && trace.getLastReceivedMessage(ServerHelloMessage.class)
                                            != trace.getFirstReceivedMessage(
                                                    ServerHelloMessage.class)) {
                                ServerHelloMessage sHello =
                                        trace.getLastReceivedMessage(ServerHelloMessage.class);
                                assertTrue(
                                        "Server accepted resumption after invalid Finished",
                                        !Arrays.equals(
                                                        cHello.getSessionId().getValue(),
                                                        sHello.getSessionId().getValue())
                                                && cHello.getSessionIdLength().getValue() > 0);
                            }
                        });
    }
}
