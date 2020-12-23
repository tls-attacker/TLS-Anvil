package de.rub.nds.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class RenegotiationExtension extends TlsGenericTest {

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @TlsTest(description = "Send a Renegotiation Extension in the Hello Message with a modified length value")
    @ScopeLimitations(DerivationType.INCLUDE_RENEGOTIATION_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    public void renegotiationExtensionLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        config.setAddRenegotiationInfoExtension(true);
        genericExtensionLengthTest(runner, argumentAccessor, config, RenegotiationInfoExtensionMessage.class);
    }
    
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @TlsTest(description = "Send a Renegotiation Extension in the Hello Message with a modified length value")
    @ScopeLimitations(DerivationType.INCLUDE_RENEGOTIATION_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    public void renegotiationExtensionLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddRenegotiationInfoExtension(true);
        genericExtensionLengthTest(runner, argumentAccessor, config, RenegotiationInfoExtensionMessage.class);
    }
    
    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @TlsTest(description = "Send a Renegotiation Extension in the Hello Message with a modified Extension Info length value")
    @ScopeLimitations(DerivationType.INCLUDE_RENEGOTIATION_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    public void renegotiationExtensionInfoLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        renegotiationExtensionInfoLengthTest(config, runner, argumentAccessor);
    }
    
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @TlsTest(description = "Send a Renegotiation Extension in the Hello Message with a modified  Extension Info length value")
    @ScopeLimitations(DerivationType.INCLUDE_RENEGOTIATION_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    public void renegotiationExtensionInfoLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        renegotiationExtensionInfoLengthTest(config, runner, argumentAccessor);
    }
    
    
    private void renegotiationExtensionInfoLengthTest(Config versionBasedConfig, WorkflowRunner runner, ArgumentsAccessor argumentAccessor) {
        versionBasedConfig.setAddRenegotiationInfoExtension(true);
        WorkflowTrace workflowTrace = setupLengthFieldTestForConfig(versionBasedConfig, runner, argumentAccessor);
        RenegotiationInfoExtensionMessage renegotiationExtension = getTargetedExtension(RenegotiationInfoExtensionMessage.class, workflowTrace);
        renegotiationExtension.setRenegotiationInfoLength(Modifiable.add(10));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
}
