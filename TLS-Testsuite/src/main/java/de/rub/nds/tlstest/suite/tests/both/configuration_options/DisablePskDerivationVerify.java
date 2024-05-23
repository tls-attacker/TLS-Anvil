/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2020 Ruhr University Bochum and TÜV Informationstechnik GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.configuration_options;

import static org.junit.Assert.assertEquals;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionParameterType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionCompoundDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePskDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@Tag("co")
public class DisablePskDerivationVerify extends Tls12Test {

    public ConditionEvaluationResult disablePskOptionTested() {
        if (ConfigurationOptionsDerivationManager.getInstance().getAllActivatedCOTypes() != null
                && ConfigurationOptionsDerivationManager.getInstance()
                        .getAllActivatedCOTypes()
                        .contains(ConfigOptionParameterType.DISABLE_PSK)) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled(
                    "The DisablePsk config option is not tested.");
        }
    }

    @AnvilTest(id = "XCO-B6aDKr3y8P")
    @MethodCondition(method = "disablePskOptionTested")
    @ModelFromScope(modelType = "EMPTY")
    @IncludeParameter("ConfigOptionParameter:DISABLE_PSK")
    public void pskCiphersuitesDisabled(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        getPreparedConfig(runner);
        // todo: implement access to container-specific extraction result
        FeatureExtractionResult extractionResult = context.getFeatureExtractionResult();
        ConfigurationOptionCompoundDerivation compoundParameter =
                this.parameterCombination.getParameter(ConfigurationOptionCompoundDerivation.class);
        DisablePskDerivation disablePskDerivation =
                compoundParameter.getDerivation(DisablePskDerivation.class);

        if (!disablePskDerivation.getSelectedValue().isOptionSet()) {
            return;
        }

        List<TlsAnalyzedProperty> expectedDisabledProperties =
                Arrays.asList(
                        TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN,
                        TlsAnalyzedProperty.SUPPORTS_PSK_RSA,
                        TlsAnalyzedProperty.SUPPORTS_PSK_DHE,
                        TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE);

        List<TlsAnalyzedProperty> nonDisabledProperties = new LinkedList<>();
        for (TlsAnalyzedProperty expectedDisabledProperty : expectedDisabledProperties) {
            if (extractionResult.getResult(expectedDisabledProperty) == TestResults.TRUE) {
                // Unexpectedly enabled.
                nonDisabledProperties.add(expectedDisabledProperty);
            }
        }
        assertEquals(
                "Unexpectedly supported features: " + nonDisabledProperties.toString(),
                0,
                nonDisabledProperties.size());
    }
}
