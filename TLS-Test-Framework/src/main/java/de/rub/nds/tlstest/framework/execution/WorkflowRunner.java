package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.CipherSuiteFilter;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.task.ITask;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.KeyX;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.*;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

public class WorkflowRunner {
    private static final Logger LOGGER = LogManager.getLogger();
    private TestContext context = null;
    private ExtensionContext extensionContext = null;

    public boolean replaceSupportedCiphersuites = false;
    public boolean appendEachSupportedCiphersuiteToSupported = false;
    public boolean replaceSelectedCiphersuite = false;

    private TestMethodConfig testMethodConfig;


    public WorkflowRunner(TestContext context) {
        this.context = context;
    }

    public AnnotatedStateContainer execute(AnnotatedStateContainer container) {
        ParallelExecutor parallelExecutor = new ParallelExecutor(container.getStates().size(), 1);
        List<State> states = container.getStates().parallelStream().map(AnnotatedState::getState).collect(Collectors.toList());
        parallelExecutor.bulkExecuteStateTasks(states);

        return container;
    }

    public AnnotatedStateContainer execute(WorkflowTrace trace, Config config) {
        AnnotatedStateContainer container = this.prepare(trace, config);
        return this.execute(container);
    }

    public AnnotatedStateContainer execute(WorkflowTrace trace) {
        return this.execute(trace, this.context.getConfig().createConfig());
    }

    public AnnotatedStateContainer prepare(WorkflowTrace trace, Config config) {
        AnnotatedState annotatedState = new AnnotatedState(new State(config, trace), testMethodConfig);
        return new AnnotatedStateContainer(this.transformState(annotatedState));
    }

    public AnnotatedStateContainer prepare(WorkflowTrace trace) {
        AnnotatedState annotatedState = new AnnotatedState(new State(this.context.getConfig().createConfig(), trace), testMethodConfig);
        return new AnnotatedStateContainer(this.transformState(annotatedState));
    }

    private List<AnnotatedState> transformStateClientTest(AnnotatedState annotatedState) {
        List<AnnotatedState> result = new ArrayList<>();
        List<CipherSuite> supported = new ArrayList<>(context.getConfig().getSiteReport().getCipherSuites());
        State state = annotatedState.getState();

        // supported only contains CipherSuites that are compatible with to
        supported.removeIf((CipherSuite i) -> !testMethodConfig.getKeyExchange().compatibleWithCiphersuite(i));

        KeyExchangeType from = testMethodConfig.getKeyExchange().provided();
        for (CipherSuite i: supported) {
            Config config = state.getConfig().createCopy();
            WorkflowTrace trace = state.getWorkflowTraceCopy();
            KeyExchangeType to = KeyExchangeType.forCipherSuite(i);

            if (replaceSupportedCiphersuites) {
                config.setDefaultServerSupportedCiphersuites(i);
            }
            else if (appendEachSupportedCiphersuiteToSupported) {
                List<CipherSuite> ciphersuites = config.getDefaultServerSupportedCiphersuites();
                ciphersuites.add(i);
                config.setDefaultServerSupportedCiphersuites(ciphersuites);
            }

            if (replaceSelectedCiphersuite) {
                config.setDefaultSelectedCipherSuite(i);
            }

            result.add(new AnnotatedState(annotatedState, new State(config, trace)));
        }

        return result;
    }


    private List<AnnotatedState> transformStateServerTest(AnnotatedState annotatedState) {
        List<AnnotatedState> result = new ArrayList<AnnotatedState>(){};
        List<CipherSuite> supported = new ArrayList<>(context.getConfig().getSiteReport().getCipherSuites());
        State state = annotatedState.getState();

        // supported only contains CipherSuites that are compatible with to
        supported.removeIf((CipherSuite i) -> !testMethodConfig.getKeyExchange().compatibleWithCiphersuite(i));

        KeyExchangeType from = testMethodConfig.getKeyExchange().provided();
        for (CipherSuite i: supported) {
            Config config = state.getConfig().createCopy();
            WorkflowTrace trace = state.getWorkflowTraceCopy();
            KeyExchangeType to = KeyExchangeType.forCipherSuite(i);
            KeyExchangeAlgorithm toKxAlg = AlgorithmResolver.getKeyExchangeAlgorithm(i);

            if (replaceSupportedCiphersuites) {
                config.setDefaultClientSupportedCiphersuites(i);
            }
            else if (appendEachSupportedCiphersuiteToSupported) {
                List<CipherSuite> ciphersuites = config.getDefaultClientSupportedCiphersuites();
                ciphersuites.add(i);
                config.setDefaultClientSupportedCiphersuites(ciphersuites);
            }

            if (replaceSupportedCiphersuites || appendEachSupportedCiphersuiteToSupported) {
                List<ReceivingAction> rAction = WorkflowTraceUtil.getReceivingActionsForMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, trace);
                ServerKeyExchangeMessage skx = new WorkflowConfigurationFactory(config).createServerKeyExchangeMessage(toKxAlg);
            }

            result.add(new AnnotatedState(annotatedState, new State(config, trace)));
        }

        return result;
    }



    private List<AnnotatedState> transformState(AnnotatedState state) {
        if (this.context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            return this.transformStateClientTest(state);
        }

        return this.transformStateServerTest(state);
    }


    public ExtensionContext getExtensionContext() {
        return extensionContext;
    }

    public void setExtensionContext(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }

    public TestMethodConfig getTestMethodConfig() {
        return testMethodConfig;
    }

    public void setTestMethodConfig(TestMethodConfig testMethodConfig) {
        this.testMethodConfig = testMethodConfig;
    }
}
