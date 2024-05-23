/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2020 Ruhr University Bochum and TÜV Informationstechnik GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.configuration_options;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionParameterType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionCompoundDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableCompressionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@Tag("co")
public class EnableCompressionDerivationVerify extends Tls12Test {

    public ConditionEvaluationResult enableCompressionOptionTested() {

        if (ConfigurationOptionsDerivationManager.getInstance().getAllActivatedCOTypes() != null
                && ConfigurationOptionsDerivationManager.getInstance()
                        .getAllActivatedCOTypes()
                        .contains(ConfigOptionParameterType.ENABLE_COMPRESSION)) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled(
                    "The EnableCompression config option is not tested.");
        }
    }

    @AnvilTest(id = "XCO-s74Cw9S5dF")
    @MethodCondition(method = "enableCompressionOptionTested")
    @ModelFromScope(modelType = "EMPTY")
    @IncludeParameter("ConfigOptionParameter:ENABLE_COMPRESSION")
    public void compressionEnabledByOption(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        getPreparedConfig(runner);
        // todo: implement access to container-specific extraction result
        FeatureExtractionResult extractionResult = context.getFeatureExtractionResult();
        ConfigurationOptionCompoundDerivation compoundParameter =
                this.parameterCombination.getParameter(ConfigurationOptionCompoundDerivation.class);
        EnableCompressionDerivation enableCompressionDerivation =
                compoundParameter.getDerivation(EnableCompressionDerivation.class);

        if (!enableCompressionDerivation.getSelectedValue().isOptionSet()) {
            return;
        }
        List<CompressionMethod> supportedNonNullCompressionMethods = new LinkedList<>();
        if (!(extractionResult.getResult(TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS)
                instanceof ListResult)) {
            // Currently not scanned in client tests
            return;
        }

        ListResult<CompressionMethod> compressionsList =
                (ListResult<CompressionMethod>)
                        extractionResult.getResult(
                                TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS);

        compressionsList.getCollection().stream()
                .filter(compression -> compression != CompressionMethod.NULL)
                .forEach(supportedNonNullCompressionMethods::add);
        assertTrue(
                "No compression method was enabled using the EnableCompressionDerivation.",
                supportedNonNullCompressionMethods.size() > 0);
    }
}
