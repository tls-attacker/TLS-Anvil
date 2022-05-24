package de.rub.nds.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@Tag("tls13")
@TlsVersion(supported = ProtocolVersion.TLS13)
@KeyExchange(supported = KeyExchangeType.ALL13)
public class PreSharedKeyExtension extends TlsGenericTest {
    
    public ConditionEvaluationResult supportsPsk() {
        if (context.getSiteReport().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK) == TestResults.TRUE
                || context.getSiteReport().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE) == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not support PSK handshakes");
        }
    }
    
    @TlsTest(description = "Send a Pre Shared Key Extension in the Hello Message with a modified length value (-1)")
    @ScopeLimitations(DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "supportsPsk")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void preSharedKeyExtensionLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupPreSharedKeyLengthFieldTest(argumentAccessor, runner);
        PreSharedKeyExtensionMessage pskExtension = getPSKExtension(workflowTrace);
        pskExtension.setExtensionLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    @TlsTest(description = "Send a Pre Shared Key Extension in the Hello Message with a modified length value (-1)")
    @ScopeLimitations(DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "supportsPsk")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void preSharedKeyExtensionIdentityListLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupPreSharedKeyLengthFieldTest(argumentAccessor, runner);
        PreSharedKeyExtensionMessage pskExtension = getPSKExtension(workflowTrace);
        pskExtension.setIdentityListLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
        
    @TlsTest(description = "Send a Pre Shared Key Extension in the Hello Message with a modified length value (-1)")
    @ScopeLimitations(DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "supportsPsk")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void preSharedKeyExtensionBinderListLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupPreSharedKeyLengthFieldTest(argumentAccessor, runner);
        PreSharedKeyExtensionMessage pskExtension = getPSKExtension(workflowTrace);
        pskExtension.setBinderListLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    private WorkflowTrace setupPreSharedKeyLengthFieldTest(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        //RFC 8446: Servers SHOULD NOT attempt to validate multiple binders;
        //rather, they SHOULD select a single PSK and validate solely the
        //binder that corresponds to that PSK.
        config.setLimitPsksToOne(Boolean.TRUE);
        adjustPreSharedKeyModes(config);
        prepareConfig(config, argumentAccessor, runner);
        return runner.generateWorkflowTrace(WorkflowTraceType.FULL_TLS13_PSK);
    }
    
    private PreSharedKeyExtensionMessage getPSKExtension(WorkflowTrace workflowTrace) {
        ClientHelloMessage secondClientHello = (ClientHelloMessage) WorkflowTraceUtil.getLastSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        return (PreSharedKeyExtensionMessage) secondClientHello.getExtension(PreSharedKeyExtensionMessage.class);
    }
}
