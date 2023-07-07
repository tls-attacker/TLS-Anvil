/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@Tag("tls12")
@TlsVersion(supported = ProtocolVersion.TLS12)
@KeyExchange(supported = KeyExchangeType.ECDH)
public class ECPointFormatExtension extends TlsGenericTest {

    @AnvilTest(
            description =
                    "Send an EC Point Format Extension in the Hello Message with a modified length value (-1)")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void pointFormatExtensionLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        genericExtensionLengthTest(
                runner, argumentAccessor, config, ECPointFormatExtensionMessage.class);
    }

    @AnvilTest(
            description =
                    "Send an EC Point Format Extension in the Hello Message with a modified formats list length value (-1)")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void pointFormatExtensionFormatsLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        ECPointFormatExtensionMessage pointFormatExtension =
                getTargetedExtension(ECPointFormatExtensionMessage.class, workflowTrace);
        pointFormatExtension.setPointFormatsLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(
                        i -> {
                            boolean skipsExtensionContent =
                                    context.getFeatureExtractionResult()
                                                    .getResult(
                                                            TlsAnalyzedProperty
                                                                    .HANDSHAKES_WITH_UNDEFINED_POINT_FORMAT)
                                            == TestResults.TRUE;
                            if (i.getWorkflowTrace().executedAsPlanned() && skipsExtensionContent) {
                                i.addAdditionalResultInfo("SUT skips over extension content");
                                return;
                            }
                            super.validateLengthTest(i);
                        });
    }
}
