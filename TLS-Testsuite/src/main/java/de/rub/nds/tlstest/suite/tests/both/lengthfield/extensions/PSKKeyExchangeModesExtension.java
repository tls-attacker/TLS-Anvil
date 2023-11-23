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
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@Tag("tls13")
@ServerTest
@TlsVersion(supported = ProtocolVersion.TLS13)
@KeyExchange(supported = KeyExchangeType.ALL13)
public class PSKKeyExchangeModesExtension extends TlsGenericTest {

    public ConditionEvaluationResult contentCanBeTested() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.ISSUES_TLS13_SESSION_TICKETS_AFTER_HANDSHAKE)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("The Extension content can be tested");
        }
        return ConditionEvaluationResult.disabled(
                "Server does not issue Session Tickets and might ignore the extension");
    }

    @AnvilTest(id = "XLF-NaN98M5Hqd")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @ExcludeParameter("INCLUDE_PSK_EXCHANGE_MODES_EXTENSION")
    public void pskKeyExchangeModesExtensionLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddPSKKeyExchangeModesExtension(true);
        genericExtensionLengthTest(
                runner, argumentAccessor, config, PSKKeyExchangeModesExtensionMessage.class);
    }

    @AnvilTest(id = "XLF-Nq22Dyhfzt")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @ExcludeParameter("INCLUDE_PSK_EXCHANGE_MODES_EXTENSION")
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
