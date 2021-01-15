/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.Arrays;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 5246, section = "7.4.1.2. Client Hello")
@ServerTest
public class ClientHello extends Tls12Test {

    @TlsTest(description = "If the list contains cipher suites the server does not recognize, support, " +
            "or wish to use, the server MUST ignore those cipher suites, and process the remaining ones as usual.")
    @Interoperability(SeverityLevel.HIGH)
    @Handshake(SeverityLevel.MEDIUM)
    public void unknownCipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCipherSuites(Modifiable.insert(new byte[]{(byte)0xfe, 0x00}, 0));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @TlsTest(description = "This vector MUST contain, and all implementations MUST support, CompressionMethod.null. " +
            "Thus, a client and server will always be able to agree on a compression method.")
    @Interoperability(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    public void unknownCompressionMethod(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCompressions(Modifiable.explicit(new byte[]{0x00, 0x04}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
    
    @RFC(number = 5246, section = "7.4.1.4.1 Signature Algorithms")
    @TlsTest(description = "The rules specified in [TLSEXT] " +
            "require servers to ignore extensions they do not understand.")
    @Interoperability(SeverityLevel.HIGH)
    @Compliance(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    public void includeUnknownExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        
        //we use a Grease Extension for which we modify the type
        GreaseExtensionMessage greaseHelperExtension = new GreaseExtensionMessage(ExtensionType.GREASE_00, 32);
        greaseHelperExtension.setExtensionType(Modifiable.explicit(new byte[]{(byte) 0xBA, (byte) 0x9F}));
        
        ClientHelloMessage clientHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        clientHello.addExtension(greaseHelperExtension);
        
        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            
            ServerHelloMessage serverHello = (ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, workflowTrace);
            if(serverHello.getExtensions() != null) {
                for(ExtensionMessage extension : serverHello.getExtensions()) {
                    assertFalse("Server negotiated the undefined Extension", Arrays.equals(extension.getExtensionType().getValue(), greaseHelperExtension.getType().getValue()));
                }
            }
        });
    }
}
