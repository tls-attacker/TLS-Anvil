package de.rub.nds.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructure;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;


public class EncryptThenMacExtension extends TlsGenericTest {
   
    
    public ConditionEvaluationResult targetCanBeTested() {
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER ||
                TestContext.getInstance().getSiteReport().getReceivedClientHello().containsExtension(ExtensionType.ENCRYPT_THEN_MAC)) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled("Target is not a server and did not include the required Extension in Client Hello");
    }
    
    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @TlsTest(description = "Send an Encrypt-Then-Mac Extension in the Hello Message with a modified formats list length value")
    @ScopeLimitations(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "targetCanBeTested")
    @MessageStructure(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    public void encryptThenMacExtensionLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        config.setAddEncryptThenMacExtension(true);
        genericExtensionLengthTest(runner, argumentAccessor, config, EncryptThenMacExtensionMessage.class);
    }
    
    @ServerTest
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @TlsTest(description = "Sending a Hello Message with a modified SessionID length")//TODO I think this description is wrong?
    @ScopeLimitations(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructure(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    public void encryptThenMacExtensionLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddEncryptThenMacExtension(true);
        genericExtensionLengthTest(runner, argumentAccessor, config, EncryptThenMacExtensionMessage.class);
    }
}
