/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsModelType;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.anvilcore.annotation.AnvilTest;

@Tag("tls13")
@ServerTest
@TlsVersion(supported = ProtocolVersion.TLS13)
@KeyExchange(supported = KeyExchangeType.ALL13)
public class PSKKeyExchangeModesExtension extends TlsGenericTest {

    public ConditionEvaluationResult contentCanBeTested() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("The Extension content can be tested");
        }
        return ConditionEvaluationResult.disabled(
                "Server does not issue Session Tickets and might ignore the extension");
    }

    @AnvilTest(
            description =
                    "Send a Pre Shared Key Exchange Modes Extension in the Hello Message with a modified length value (-1)")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @ScopeLimitations(TlsParameterType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void pskKeyExchangeModesExtensionLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddPSKKeyExchangeModesExtension(true);
        genericExtensionLengthTest(
                runner, argumentAccessor, config, PSKKeyExchangeModesExtensionMessage.class);
    }

    @AnvilTest(
            description =
                    "Send a Pre Shared Key Exchange Modes Extension in the Hello Message with a modified length value (-1)")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @ScopeLimitations(TlsParameterType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    @MethodCondition(method = "contentCanBeTested")
    public void pskKeyExchangeModesExtensionListLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddPSKKeyExchangeModesExtension(true);
        WorkflowTrace workflowTrace =
                setupLengthFieldTestForConfig(config, runner, argumentAccessor);
        PSKKeyExchangeModesExtensionMessage keyExchangeModes =
                getTargetedExtension(PSKKeyExchangeModesExtensionMessage.class, workflowTrace);
        keyExchangeModes.setKeyExchangeModesListLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }
}
