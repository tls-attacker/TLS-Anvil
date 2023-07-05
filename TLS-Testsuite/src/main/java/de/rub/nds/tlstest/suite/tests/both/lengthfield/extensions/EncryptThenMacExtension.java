/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
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
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.TlsModelType;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class EncryptThenMacExtension extends TlsGenericTest {

    public ConditionEvaluationResult targetCanBeTested() {
        if (TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER
                || ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                        .getReceivedClientHello()
                        .containsExtension(ExtensionType.ENCRYPT_THEN_MAC)) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled(
                "Target is not a server and did not include the required Extension in Client Hello");
    }

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @TlsTest(
            description =
                    "Send an Encrypt-Then-Mac Extension in the Hello Message with a modified length value (+1)")
    @ScopeLimitations(TlsParameterType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)
    @ModelFromScope(baseModel = TlsModelType.LENGTHFIELD)
    @MethodCondition(method = "targetCanBeTested")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void encryptThenMacExtensionLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        config.setAddEncryptThenMacExtension(true);
        emptyExtensionLengthTest(
                runner, argumentAccessor, config, EncryptThenMacExtensionMessage.class);
    }

    @ServerTest
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @TlsTest(
            description =
                    "Send an Encrypt-Then-Mac Extension in the Hello Message with a modified length value (+1)")
    @ScopeLimitations(TlsParameterType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)
    @ModelFromScope(baseModel = TlsModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void encryptThenMacExtensionLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddEncryptThenMacExtension(true);
        emptyExtensionLengthTest(
                runner, argumentAccessor, config, EncryptThenMacExtensionMessage.class);
    }
}
