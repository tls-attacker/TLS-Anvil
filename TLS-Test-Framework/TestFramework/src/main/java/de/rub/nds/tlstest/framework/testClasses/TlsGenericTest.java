/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.testClasses;


import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@Tag("lengthTest")
public class TlsGenericTest extends TlsBaseTest {
    @Override
    public Config getConfig() {
        throw new RuntimeException("Invalid method, call context.getConfig.createConfig() instead");
    }
    
    public WorkflowTrace setupLengthFieldTestTls13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = context.getConfig().createTls13Config();
        return setupLengthFieldTestForConfig(c, runner, argumentAccessor);
    }
    
    public WorkflowTrace setupLengthFieldTestTls12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();
        return setupLengthFieldTestForConfig(c, runner, argumentAccessor);
    }

    @Override
    public Config prepareConfig(Config config, ArgumentsAccessor argAccessor, WorkflowRunner runner) {
        super.prepareConfig(config, argAccessor, runner);
        config.setStopTraceAfterUnexpected(true);
        config.getDefaultServerConnection().setTimeout(1000);
        config.getDefaultServerConnection().setFirstTimeout(5000);
        config.getDefaultClientConnection().setTimeout(1000);
        config.getDefaultClientConnection().setFirstTimeout(5000);
        return config;
    }
    
    
    
    public WorkflowTrace setupLengthFieldTestForConfig(Config config, WorkflowRunner runner, ArgumentsAccessor argumentAccessor) {
        prepareConfig(config, argumentAccessor, runner);
        return runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
    }
    
    public void validateLengthTest(AnnotatedState i) {
        assertFalse("Workflow could be executed as planned for " + derivationContainer.toString(), i.getWorkflowTrace().executedAsPlanned());

        SocketState socketState = i.getState().getTlsContext().getFinalSocketState();
        boolean socketClosed = (socketState == SocketState.SOCKET_EXCEPTION || socketState == SocketState.CLOSED || socketState == SocketState.IO_EXCEPTION);
        assertTrue("Socket not closed", socketClosed);

        AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        if (msg == null) return;

        assertEquals("No fatal alert received", AlertLevel.FATAL.getValue(), msg.getLevel().getValue().byteValue());
    }
    
    public boolean isClientTest() {
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            return true;
        }
        return false;
    }
    
    protected void genericExtensionLengthTest(WorkflowRunner runner, ArgumentsAccessor argumentAccessor, Config config, Class<? extends ExtensionMessage> extensionMessageClass) {
        WorkflowTrace workflowTrace = setupLengthFieldTestForConfig(config, runner, argumentAccessor); 
        ExtensionMessage extensionMessage = getTargetedExtension(extensionMessageClass, workflowTrace);
        extensionMessage.setExtensionLength(Modifiable.add(10));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(this::validateLengthTest);
    }
    
    public <T extends ExtensionMessage> T getTargetedExtension(Class<? extends ExtensionMessage> clazz, WorkflowTrace workflowTrace) {
        if(isClientTest()) {
            ExtensionMessage extension = getExtensionFromHello(clazz, workflowTrace);
            if(extension == null) {
                extension = getExtensionFromEncryptedExtensions(clazz, workflowTrace);
            }
            return (T) extension;
        }
        return getExtensionFromHello(clazz, workflowTrace);
    }
    
    private <T extends ExtensionMessage> T getExtensionFromEncryptedExtensions(Class<? extends ExtensionMessage> clazz, WorkflowTrace workflowTrace) {
        EncryptedExtensionsMessage encryptedExtensionsMessage = (EncryptedExtensionsMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.ENCRYPTED_EXTENSIONS, workflowTrace);
        return (T) encryptedExtensionsMessage.getExtension(clazz);
    }
    
    public <T extends ExtensionMessage> T getExtensionFromHello(Class<? extends ExtensionMessage> clazz, WorkflowTrace workflowTrace) {
        HandshakeMessage requiredHelloMessage;
        if(isClientTest()) {
            requiredHelloMessage = WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_HELLO, workflowTrace);
        } else {
            requiredHelloMessage = WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        }
        return (T) requiredHelloMessage.getExtension(clazz);
    }
}
