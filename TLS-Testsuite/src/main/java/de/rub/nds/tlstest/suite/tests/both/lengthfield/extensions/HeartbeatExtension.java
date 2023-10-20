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
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class HeartbeatExtension extends TlsGenericTest {

    public ConditionEvaluationResult targetCanBeTested() {
        if (TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER
                || ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                        .getReceivedClientHello()
                        .containsExtension(ExtensionType.HEARTBEAT)) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled(
                "Target is not a server and did not include the required Extension in Client Hello");
    }

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @AnvilTest(id = "XLF-eouPKJt7Ht")
    @ExcludeParameter("INCLUDE_HEARTBEAT_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MethodCondition(method = "targetCanBeTested")
    public void heartbeatExtensionLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        config.setAddHeartbeatExtension(true);
        genericExtensionLengthTest(
                runner, argumentAccessor, config, HeartbeatExtensionMessage.class);
    }

    @Tag("tls13")
    @ServerTest
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @AnvilTest(id = "XLF-dQABdv21Am")
    @ExcludeParameter("INCLUDE_HEARTBEAT_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void heartbeatExtensionLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddHeartbeatExtension(true);
        genericExtensionLengthTest(
                runner, argumentAccessor, config, HeartbeatExtensionMessage.class);
    }
}
