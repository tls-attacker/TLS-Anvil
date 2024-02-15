/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsLengthfieldTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class SignatureAndHashAlgorithmsExtension extends TlsLengthfieldTest {

    @TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @AnvilTest(id = "XLF-Dtq2iEmPmd")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void signatureAndHashAlgorithmsExtensionLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        genericExtensionLengthTest(
                runner, argumentAccessor, config, SignatureAndHashAlgorithmsExtensionMessage.class);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @AnvilTest(id = "XLF-s6s3mWStow")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void signatureAndHashAlgorithmsExtensionLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        genericExtensionLengthTest(
                runner, argumentAccessor, config, SignatureAndHashAlgorithmsExtensionMessage.class);
    }

    @Tag("tls12")
    @TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @AnvilTest(id = "XLF-x666dC8D1Z")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void signatureAndHashAlgorithmsListLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        signatureAndHashAlgorithmsListLengthTest(config, runner, argumentAccessor);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @AnvilTest(id = "XLF-Qm9jhF6Pn8")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void signatureAndHashAlgorithmsListLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        signatureAndHashAlgorithmsListLengthTest(config, runner, argumentAccessor);
    }

    private void signatureAndHashAlgorithmsListLengthTest(
            Config versionBasedConfig, WorkflowRunner runner, ArgumentsAccessor argumentAccessor) {
        versionBasedConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        WorkflowTrace workflowTrace =
                setupLengthFieldTestForConfig(versionBasedConfig, runner, argumentAccessor);
        SignatureAndHashAlgorithmsExtensionMessage sigAndHashAlgorithmsExtension =
                getTargetedExtension(
                        SignatureAndHashAlgorithmsExtensionMessage.class, workflowTrace);
        sigAndHashAlgorithmsExtension.setSignatureAndHashAlgorithmsLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }
}
