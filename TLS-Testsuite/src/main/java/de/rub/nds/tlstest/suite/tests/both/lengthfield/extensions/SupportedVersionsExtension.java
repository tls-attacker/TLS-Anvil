package de.rub.nds.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@Tag("tls13")
@TlsVersion(supported = ProtocolVersion.TLS13)
@KeyExchange(supported = KeyExchangeType.ALL13)
public class SupportedVersionsExtension extends TlsGenericTest {
    
    @TlsTest(description = "Send a Supported Versions Extension in the Hello Message with a modified algorithm list length value")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    public void supportedVersionsExtensionLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        genericExtensionLengthTest(runner, argumentAccessor, config, SupportedVersionsExtensionMessage.class);
    }
    
    @ServerTest
    @TlsTest(description = "Send a Supported Versions Extension in the Hello Message with a modified algorithm list length value")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    public void supportedVersionsListLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        SupportedVersionsExtensionMessage supportedVersions = getTargetedExtension(SupportedVersionsExtensionMessage.class, workflowTrace);
        supportedVersions.setSupportedVersionsLength(Modifiable.add(10));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(this::validateLengthTest);
    }
}
