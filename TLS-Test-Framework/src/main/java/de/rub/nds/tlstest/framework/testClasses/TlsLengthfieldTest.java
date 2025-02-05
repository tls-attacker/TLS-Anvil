/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.testClasses;

import static org.junit.Assert.assertFalse;

import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import org.junit.jupiter.api.Tag;

@Tag("lengthTest")
public class TlsLengthfieldTest extends TlsBaseTest {
    @Override
    public Config getConfig() {
        throw new RuntimeException("Invalid method, call context.getConfig.createConfig() instead");
    }

    public WorkflowTrace setupLengthFieldTestTls13(WorkflowRunner runner) {
        Config c = context.getConfig().createTls13Config();
        return setupLengthFieldTestForConfig(c, runner);
    }

    public WorkflowTrace setupLengthFieldTestTls12(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();
        return setupLengthFieldTestForConfig(c, runner);
    }

    @Override
    public Config prepareConfig(Config config, WorkflowRunner runner) {
        super.prepareConfig(config, runner);
        config.setStopTraceAfterUnexpected(true);
        return config;
    }

    public WorkflowTrace setupLengthFieldTestForConfig(Config config, WorkflowRunner runner) {
        prepareConfig(config, runner);
        return runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
    }

    public void validateLengthTest(State state, AnvilTestCase testCase) {
        Validator.checkForUnknownMessage(state, testCase);
        assertFalse(
                "Workflow could be executed as planned for " + parameterCombination.toString(),
                state.getWorkflowTrace().executedAsPlanned());
        if (!state.getTlsContext().isReceivedTransportHandlerException()) {
            Validator.receivedFatalAlert(state, testCase, false);
        }
    }

    public boolean isClientTest() {
        if (TestContext.getInstance().getConfig().getTestEndpointMode()
                == TestEndpointType.CLIENT) {
            return true;
        }
        return false;
    }

    protected void genericExtensionLengthTest(
            WorkflowRunner runner,
            AnvilTestCase testCase,
            Config config,
            Class<? extends ExtensionMessage> extensionMessageClass) {
        WorkflowTrace workflowTrace = setupLengthFieldTestForConfig(config, runner);
        ExtensionMessage extensionMessage =
                getTargetedExtension(extensionMessageClass, workflowTrace);
        extensionMessage.setExtensionLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    protected void emptyExtensionLengthTest(
            WorkflowRunner runner,
            AnvilTestCase testCase,
            Config config,
            Class<? extends ExtensionMessage> extensionMessageClass) {
        WorkflowTrace workflowTrace = setupLengthFieldTestForConfig(config, runner);
        ExtensionMessage extensionMessage =
                getTargetedExtension(extensionMessageClass, workflowTrace);
        extensionMessage.setExtensionLength(Modifiable.add(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    public <T extends ExtensionMessage> T getTargetedExtension(
            Class<? extends ExtensionMessage> clazz, WorkflowTrace workflowTrace) {
        if (isClientTest()) {
            ExtensionMessage extension = getExtensionFromHello(clazz, workflowTrace);
            if (extension == null) {
                extension = getExtensionFromEncryptedExtensions(clazz, workflowTrace);
            }
            return (T) extension;
        }
        return getExtensionFromHello(clazz, workflowTrace);
    }

    private <T extends ExtensionMessage> T getExtensionFromEncryptedExtensions(
            Class<? extends ExtensionMessage> clazz, WorkflowTrace workflowTrace) {
        EncryptedExtensionsMessage encryptedExtensionsMessage =
                (EncryptedExtensionsMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.ENCRYPTED_EXTENSIONS);
        return (T) encryptedExtensionsMessage.getExtension(clazz);
    }

    public <T extends ExtensionMessage> T getExtensionFromHello(
            Class<? extends ExtensionMessage> clazz, WorkflowTrace workflowTrace) {
        HandshakeMessage requiredHelloMessage;
        if (isClientTest()) {
            requiredHelloMessage =
                    (HandshakeMessage)
                            WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                    workflowTrace, HandshakeMessageType.SERVER_HELLO);
        } else {
            requiredHelloMessage =
                    (HandshakeMessage)
                            WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                    workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        }
        return (T) requiredHelloMessage.getExtension(clazz);
    }
}
