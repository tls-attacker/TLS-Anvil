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
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsLengthfieldTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class RenegotiationExtension extends TlsLengthfieldTest {

    @Tag("tls12")
    @TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @AnvilTest(id = "XLF-oU4NN7JA83")
    @ExcludeParameter("INCLUDE_RENEGOTIATION_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void renegotiationExtensionLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        config.setAddRenegotiationInfoExtension(true);
        genericExtensionLengthTest(
                runner, argumentAccessor, config, RenegotiationInfoExtensionMessage.class);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @AnvilTest(id = "XLF-iqfnLSxRsR")
    @ExcludeParameter("INCLUDE_RENEGOTIATION_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void renegotiationExtensionLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddRenegotiationInfoExtension(true);
        genericExtensionLengthTest(
                runner, argumentAccessor, config, RenegotiationInfoExtensionMessage.class);
    }

    @Tag("tls12")
    @TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @AnvilTest(id = "XLF-AxKvemiN6n")
    @ExcludeParameter("INCLUDE_RENEGOTIATION_EXTENSION")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void renegotiationExtensionInfoLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        renegotiationExtensionInfoLengthTest(config, runner, argumentAccessor);
    }

    private void renegotiationExtensionInfoLengthTest(
            Config versionBasedConfig, WorkflowRunner runner, ArgumentsAccessor argumentAccessor) {
        versionBasedConfig.setAddRenegotiationInfoExtension(true);
        WorkflowTrace workflowTrace =
                setupLengthFieldTestForConfig(versionBasedConfig, runner, argumentAccessor);
        RenegotiationInfoExtensionMessage renegotiationExtension =
                getTargetedExtension(RenegotiationInfoExtensionMessage.class, workflowTrace);
        renegotiationExtension.setRenegotiationInfoLength(Modifiable.add(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }
}
