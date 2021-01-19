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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Crypto;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeature;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructure;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.Arrays;

import static org.junit.Assert.*;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "4.1.3 Server Hello")
@ServerTest
public class ServerHello extends Tls13Test {

    public ConditionEvaluationResult supportsTls12() {
        if (context.getSiteReport().getVersions().contains(ProtocolVersion.TLS12))
            return ConditionEvaluationResult.enabled("");
        return ConditionEvaluationResult.disabled("No TLS 1.2 supported");
    }

    @TlsTest(description = "In TLS 1.3, the TLS server indicates its version using the \"supported_versions\" " +
            "extension (Section 4.2.1), and the legacy_version field MUST be " +
            "set to 0x0303, which is the version number for TLS 1.2.")
    @Interoperability(SeverityLevel.HIGH)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    public void testLegacyVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new CertificateVerifyMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, msg);
            assertArrayEquals("Invalid legacy version", new byte[]{0x03, 0x03}, msg.getProtocolVersion().getValue());
        });
    }

    @TlsTest(description = "The last 8 bytes MUST be overwritten as described " +
            "below if negotiating TLS 1.2 or TLS 1.1, but the remaining bytes MUST be random.")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @Interoperability(SeverityLevel.HIGH)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    public void testServerRandomFor12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, msg);
            byte[] random = msg.getRandom().getValue();
            assertArrayEquals("Invalid random", new byte[]{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01},
                    Arrays.copyOfRange(random, random.length - 8, random.length));
        });
    }

    @TlsTest(description = "A client which receives a legacy_session_id_echo " +
            "field that does not match what it sent in the ClientHello MUST " +
            "abort the handshake with an \"illegal_parameter\" alert.")
    @Interoperability(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.MEDIUM)
    @Alert(SeverityLevel.MEDIUM)
    public void testSessionId(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        byte[] sessionId = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        c.setDefaultClientSessionId(sessionId);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new CertificateVerifyMessage(c))
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, msg);
            assertArrayEquals("Session ID not echoed", sessionId, msg.getSessionId().getValue());
        });
    }

    @TlsTest(description = "legacy_compression_method: A single byte which " +
            "MUST have the value 0.")
    @Interoperability(SeverityLevel.HIGH)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.MEDIUM)
    public void testCompressionValue(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, c).validateFinal(i -> {
            assertEquals("invalid compression method",
                    0,
                    i.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class).getSelectedCompressionMethod().getValue().byteValue()
            );
        });
    }

}
