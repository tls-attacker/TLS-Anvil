package de.rub.nds.tlstest.suite.tests.both.lengthField;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;


@ClientTest
@Tag("tls12")
@TlsVersion(supported = ProtocolVersion.TLS12)
@KeyExchange(supported = KeyExchangeType.ALL12)
public class ServerHelloDone extends TlsGenericTest {

    @TlsTest(description = "Send a Server Hello Done Message with a modified length value")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    public void serverHelloDoneLengthTest(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        ServerHelloDoneMessage serverHelloDone = (ServerHelloDoneMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_HELLO_DONE, workflowTrace);
        serverHelloDone.setLength(Modifiable.add(10));   
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest); 
    }
}
