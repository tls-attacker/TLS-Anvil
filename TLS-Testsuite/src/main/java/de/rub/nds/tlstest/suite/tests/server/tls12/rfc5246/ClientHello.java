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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
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
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.Arrays;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 5246, section = "7.4.1.2. Client Hello")
@ServerTest
public class ClientHello extends Tls12Test {

    @TlsTest(description = "If the list contains cipher suites the server does not recognize, support, " +
            "or wish to use, the server MUST ignore those cipher suites, and process the remaining ones as usual.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
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
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
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
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
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
    
    @TlsTest(description = "Send a ClientHello that offers many cipher suites")
    @ScopeLimitations(DerivationType.INCLUDE_GREASE_CIPHER_SUITES)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void offerManyCipherSuites(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        
        //add pseudo cipher suites to reach 408, which is the sum of all
        //defined values and GREASE values
        CipherSuite selectedCipherSuite = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();
        byte[] explicitCipherSuites = new byte[408 * 2];
        byte firstByte = 0x0A;
        byte secondByte = 0;
        for(int i = 0; i < 407 * 2; i = i + 2) {
            explicitCipherSuites[i] = firstByte;
            explicitCipherSuites[i + 1] = secondByte;
            if(secondByte == (byte) 0xFF) {
                firstByte++;
            }
            secondByte++;
        }
        explicitCipherSuites[814] = selectedCipherSuite.getByteValue()[0];
        explicitCipherSuites[815] = selectedCipherSuite.getByteValue()[1];
        
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCipherSuites(Modifiable.explicit(explicitCipherSuites));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
        
    }
    
    @TlsTest(description = "A server MUST accept ClientHello " +
        "messages both with and without the extensions field")
    @ScopeLimitations({DerivationType.INCLUDE_ALPN_EXTENSION, DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION, DerivationType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION, DerivationType.INCLUDE_HEARTBEAT_EXTENSION, DerivationType.INCLUDE_PADDING_EXTENSION, DerivationType.INCLUDE_RENEGOTIATION_EXTENSION, DerivationType.INCLUDE_SESSION_TICKET_EXTENSION, DerivationType.MAX_FRAGMENT_LENGTH, DerivationType.INCLUDE_GREASE_SIG_HASH_ALGORITHMS, DerivationType.INCLUDE_GREASE_NAMED_GROUPS, DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION})
    @KeyExchange(supported = {KeyExchangeType.DH, KeyExchangeType.RSA})
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void leaveOutExtensions(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        ClientHelloMessage clientHello = workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        clientHello.setExtensionBytes(Modifiable.explicit(new byte [0]));
        runner.execute(workflowTrace, config).validateFinal(Validator::executedAsPlanned);
    }
}
