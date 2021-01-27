package de.rub.nds.tlstest.suite.tests.both.lengthfield;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructure;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class Finished extends TlsGenericTest {
    
    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @TlsTest(description = "Send a Finished Message with a modified length value")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructure(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    public void finishedLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        finishedLengthTest(workflowTrace, runner);
    }
    
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @TlsTest(description = "Send a Finished Message with a modified length value")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructure(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    public void finishedLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        finishedLengthTest(workflowTrace, runner);
    }
    
    private void finishedLengthTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
       FinishedMessage finishedMessage = (FinishedMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.FINISHED, workflowTrace);
       finishedMessage.setLength(Modifiable.add(10)); 
       if((runner.getPreparedConfig().getHighestProtocolVersion() != ProtocolVersion.TLS13 && context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT)
               || (runner.getPreparedConfig().getHighestProtocolVersion() == ProtocolVersion.TLS13 && context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER)) {
           workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
           runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(Validator::receivedFatalAlert);
       } else {
           runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
       }
    }
}
