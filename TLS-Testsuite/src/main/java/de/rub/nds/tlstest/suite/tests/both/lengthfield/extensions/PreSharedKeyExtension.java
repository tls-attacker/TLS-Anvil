/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsLengthfieldTest;
import de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446.PreSharedKey;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
@Tag("tls13")
@TlsVersion(supported = ProtocolVersion.TLS13)
@KeyExchange(supported = KeyExchangeType.ALL13)
public class PreSharedKeyExtension extends TlsLengthfieldTest {

    public ConditionEvaluationResult supportsPsk() {
        if (context.getFeatureExtractionResult().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK)
                        == TestResults.TRUE
                || context.getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE)
                        == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled(PreSharedKey.PSK_HANDSHAKES_NOT_SUPPORTED);
        }
    }

    @AnvilTest(id = "XLF-XHw8giy6m4")
    @ExcludeParameter("INCLUDE_PSK_EXCHANGE_MODES_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MethodCondition(method = "supportsPsk")
    public void preSharedKeyExtensionLength(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupPreSharedKeyLengthFieldTest(runner);
        PreSharedKeyExtensionMessage pskExtension = getPSKExtension(workflowTrace);
        pskExtension.setExtensionLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    @AnvilTest(id = "XLF-kwNxe25ef8")
    @ExcludeParameter("INCLUDE_PSK_EXCHANGE_MODES_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MethodCondition(method = "supportsPsk")
    public void preSharedKeyExtensionIdentityListLength(
            AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupPreSharedKeyLengthFieldTest(runner);
        PreSharedKeyExtensionMessage pskExtension = getPSKExtension(workflowTrace);
        pskExtension.setIdentityListLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    @AnvilTest(id = "XLF-4L65zmLyuG")
    @ExcludeParameter("INCLUDE_PSK_EXCHANGE_MODES_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MethodCondition(method = "supportsPsk")
    public void preSharedKeyExtensionBinderListLength(
            AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupPreSharedKeyLengthFieldTest(runner);
        PreSharedKeyExtensionMessage pskExtension = getPSKExtension(workflowTrace);
        pskExtension.setBinderListLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    private WorkflowTrace setupPreSharedKeyLengthFieldTest(WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        // RFC 8446: Servers SHOULD NOT attempt to validate multiple binders;
        // rather, they SHOULD select a single PSK and validate solely the
        // binder that corresponds to that PSK.
        config.setLimitPsksToOne(Boolean.TRUE);
        adjustPreSharedKeyModes(config);
        prepareConfig(config, runner);
        return runner.generateWorkflowTrace(WorkflowTraceType.FULL_TLS13_PSK);
    }

    private PreSharedKeyExtensionMessage getPSKExtension(WorkflowTrace workflowTrace) {
        ClientHelloMessage secondClientHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        return (PreSharedKeyExtensionMessage)
                secondClientHello.getExtension(PreSharedKeyExtensionMessage.class);
    }
}
