package de.rub.nds.tlstest.suite.tests.both.lengthField.extensions;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class ALPNExtension extends TlsGenericTest {
    
    public ConditionEvaluationResult targetCanBeTested() {
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER ||
                TestContext.getInstance().getSiteReport().getReceivedClientHello().containsExtension(ExtensionType.ALPN)) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled("Target is not a server and did not include the required Extension in Client Hello");
    }
    
    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @TlsTest(description = "Send an ALPN Extension in the Hello Message with a modified length value")
    @ScopeLimitations(DerivationType.INCLUDE_ALPN_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "targetCanBeTested")
    public void alpnExtensionLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        config.setAddAlpnExtension(true);
        config.setDefaultProposedAlpnProtocols("http/1.1", "spdy/1", "spdy/2", "spdy/3", "stun.turn",
                "stun.nat-discovery", "h2", "h2c", "webrtc", "c-webrtc", "ftp", "imap", "pop3", "managesieve");
        genericExtensionLengthTest(runner, argumentAccessor, config, AlpnExtensionMessage.class);
    }

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @TlsTest(description = "Send an ALPN Extension in the Hello Message with a modified protocols list length value")
    @ScopeLimitations(DerivationType.INCLUDE_ALPN_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "targetCanBeTested")
    public void alpnProposedAlpnProtocolsLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        alpnExtensionProposedAlpnProtocolsLengthTest(config, runner, argumentAccessor);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @TlsTest(description = "Send an ALPN Extension in the Hello Message with a modified length value")
    @ScopeLimitations(DerivationType.INCLUDE_ALPN_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "targetCanBeTested")
    public void alpnExtensionLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddAlpnExtension(true);
        config.setDefaultProposedAlpnProtocols("http/1.1", "spdy/1", "spdy/2", "spdy/3", "stun.turn",
                "stun.nat-discovery", "h2", "h2c", "webrtc", "c-webrtc", "ftp", "imap", "pop3", "managesieve");
        genericExtensionLengthTest(runner, argumentAccessor, config, AlpnExtensionMessage.class);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @TlsTest(description = "Send an ALPN Extension in the Hello Message with a modified protocols list length value")
    @ScopeLimitations(DerivationType.INCLUDE_ALPN_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "targetCanBeTested")
    public void alpnProposedAlpnProtocolsLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        alpnExtensionProposedAlpnProtocolsLengthTest(config, runner, argumentAccessor);
    }

    private void alpnExtensionProposedAlpnProtocolsLengthTest(Config versionBasedConfig, WorkflowRunner runner, ArgumentsAccessor argumentAccessor) {
        versionBasedConfig.setAddAlpnExtension(true);
        versionBasedConfig.setDefaultProposedAlpnProtocols("http/1.1", "spdy/1", "spdy/2", "spdy/3", "stun.turn",
                "stun.nat-discovery", "h2", "h2c", "webrtc", "c-webrtc", "ftp", "imap", "pop3", "managesieve");
        WorkflowTrace workflowTrace = setupLengthFieldTestForConfig(versionBasedConfig, runner, argumentAccessor);
        AlpnExtensionMessage alpnExtension = getTargetedExtension(AlpnExtensionMessage.class, workflowTrace);
        alpnExtension.setProposedAlpnProtocolsLength(Modifiable.add(10));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
}
