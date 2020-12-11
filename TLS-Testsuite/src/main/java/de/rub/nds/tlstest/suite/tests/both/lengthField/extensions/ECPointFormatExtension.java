package de.rub.nds.tlstest.suite.tests.both.lengthField.extensions;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
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

@Tag("tls12")
@TlsVersion(supported = ProtocolVersion.TLS12)
@KeyExchange(supported = KeyExchangeType.ECDH)
public class ECPointFormatExtension extends TlsGenericTest {

    @TlsTest(description = "Send an EC Point Format Extension in the Hello Message with a modified length value")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    public void pointFormatExtensionLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        genericExtensionLengthTest(runner, argumentAccessor, config, ECPointFormatExtensionMessage.class);
    }

    @TlsTest(description = "Send an EC Point Format Extension in the Hello Message with a modified formats list length value")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    public void pointFormatExtensionFormatsLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        ECPointFormatExtensionMessage pointFormatExtension = getTargetedExtension(ECPointFormatExtensionMessage.class, workflowTrace);
        pointFormatExtension.setPointFormatsLength(Modifiable.add(10));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
}
