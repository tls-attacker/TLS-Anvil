package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "D.4.  Middlebox Compatibility Mode")
public class MiddleboxCompatibility extends Tls13Test {
    
    public ConditionEvaluationResult sendsHelloRetryRequestForEmptyKeyShare() {
        if (context.getSiteReport().getResult(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST) == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Target does not send a Hello Retry Request");
    }
    
    @TlsTest(description = "Either side can send change_cipher_spec at any time during "
            + "the handshake, as they must be ignored by the peer, but if "
            + "the client sends a non-empty session ID, the server MUST "
            + "send the change_cipher_spec as described in this appendix.")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @Tag("new")
    public void respectsClientCompatibilityWish(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.getFirstSendMessage(ClientHelloMessage.class).setSessionId(Modifiable.explicit(config.getDefaultClientTicketResumptionSessionId()));
        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            assertTrue("Did not receive a compatibility CCS", WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.CHANGE_CIPHER_SPEC, i.getWorkflowTrace()));
            List<ProtocolMessage> receivedMessages = WorkflowTraceUtil.getAllReceivedMessages(workflowTrace);
            for(ProtocolMessage receivedMessage: receivedMessages) {
                if(receivedMessage instanceof ServerHelloMessage) {
                    assertTrue("Server did not send the compatibility CCS after the Server Hello", receivedMessages.get(receivedMessages.indexOf(receivedMessage) + 1) instanceof ChangeCipherSpecMessage);
                }
            }
        });
    }
    
    @TlsTest(description = "Either side can send change_cipher_spec at any time during "
            + "the handshake, as they must be ignored by the peer, but if "
            + "the client sends a non-empty session ID, the server MUST "
            + "send the change_cipher_spec as described in this appendix.")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @MethodCondition(method = "sendsHelloRetryRequestForEmptyKeyShare")
    @Tag("new")
    public void respectsClientCompatibilityWishWithHrr(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        //enforce HRR
        config.setDefaultClientKeyShareNamedGroups(new LinkedList<>());
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.getFirstSendMessage(ClientHelloMessage.class).setSessionId(Modifiable.explicit(config.getDefaultClientTicketResumptionSessionId()));
        runner.execute(workflowTrace, config).validateFinal(i -> {
            assertTrue("Did not receive a compatibility CCS", WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.CHANGE_CIPHER_SPEC, i.getWorkflowTrace()));
            List<ProtocolMessage> receivedMessages = WorkflowTraceUtil.getAllReceivedMessages(workflowTrace);
            for(ProtocolMessage receivedMessage: receivedMessages) {
                if(receivedMessage instanceof ServerHelloMessage) {
                    assertTrue("Server did not send the compatibility CCS after the Hello Retry Request", receivedMessages.get(receivedMessages.indexOf(receivedMessage) + 1) instanceof ChangeCipherSpecMessage);
                }
            }
        });
    }
}
