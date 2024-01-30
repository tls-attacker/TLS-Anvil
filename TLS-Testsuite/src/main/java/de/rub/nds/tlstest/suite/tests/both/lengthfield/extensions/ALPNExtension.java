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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
public class ALPNExtension extends TlsGenericTest {

    public ConditionEvaluationResult targetCanBeTested() {
        ServerFeatureExtractionResult extractionResult =
                (ServerFeatureExtractionResult) context.getFeatureExtractionResult();
        if (extractionResult.getNegotiableExtensions() != null) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled(
                "Target is not a server and did not include the required Extension in Client Hello");
    }

    public ConditionEvaluationResult contentCanBeTested() {
        ServerFeatureExtractionResult extractionResult =
                (ServerFeatureExtractionResult) context.getFeatureExtractionResult();

        if (extractionResult.getNegotiableExtensions() != null
                && extractionResult.getNegotiableExtensions().contains(ExtensionType.ALPN)) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled(
                "Target is not a server and did not include the required Extension in Client Hello");
    }

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @AnvilTest(id = "XLF-MNJikTAwVv")
    @ExcludeParameter("INCLUDE_ALPN_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MethodCondition(method = "targetCanBeTested")
    public void alpnExtensionLengthTLS12(WorkflowRunner runner, AnvilTestCase testCase) {
        Config config = context.getConfig().createConfig();
        config.setAddAlpnExtension(true);
        genericExtensionLengthTest(runner, testCase, config, AlpnExtensionMessage.class);
    }

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @AnvilTest(id = "XLF-3D5DbZQNVB")
    @ExcludeParameter("INCLUDE_ALPN_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MethodCondition(method = "contentCanBeTested")
    public void alpnProposedAlpnProtocolsLengthTLS12(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        alpnExtensionProposedAlpnProtocolsLengthTest(config, runner, testCase);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @AnvilTest(id = "XLF-yU3WPbhb9z")
    @ExcludeParameter("INCLUDE_ALPN_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MethodCondition(method = "targetCanBeTested")
    public void alpnExtensionLengthTLS13(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddAlpnExtension(true);
        genericExtensionLengthTest(runner, testCase, config, AlpnExtensionMessage.class);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @AnvilTest(id = "XLF-47Go2svX7H")
    @ExcludeParameter("INCLUDE_ALPN_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MethodCondition(method = "contentCanBeTested")
    public void alpnProposedAlpnProtocolsLengthTLS13(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        alpnExtensionProposedAlpnProtocolsLengthTest(config, runner, testCase);
    }

    private void alpnExtensionProposedAlpnProtocolsLengthTest(
            Config versionBasedConfig, WorkflowRunner runner, AnvilTestCase testCase) {
        versionBasedConfig.setAddAlpnExtension(true);
        WorkflowTrace workflowTrace = setupLengthFieldTestForConfig(versionBasedConfig, runner);
        AlpnExtensionMessage alpnExtension =
                getTargetedExtension(AlpnExtensionMessage.class, workflowTrace);
        alpnExtension.setProposedAlpnProtocolsLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }
}
