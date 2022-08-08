/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.configuration_options;


import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.ParameterExtensionManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionCompoundDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePskDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

@Tag("co")
public class DisablePskDerivationVerify extends Tls12Test {

    public ConditionEvaluationResult disablePskOptionTested() {
        if (ParameterExtensionManager.getInstance().getLoadedExtensions().contains("ConfigurationOptionsExtension")) {
            if (ConfigurationOptionsDerivationManager.getInstance().getAllActivatedCOTypes().contains(ConfigOptionDerivationType.DisablePsk)){
                return ConditionEvaluationResult.enabled("");
            }
            else {
                return ConditionEvaluationResult.disabled("The DisablePsk option is not tested.");
            }
        } else {
            return ConditionEvaluationResult.disabled("Configuration options are not tested.");
        }
    }

    @TlsTest(description = "The configuration option disablePsk disables all PSK ciphersuites.")
    @MethodCondition(method = "disablePskOptionTested")
    @ModelFromScope(baseModel = ModelType.EMPTY)
    @ScopeExtensions("ConfigOptionDerivationType.ConfigurationOptionCompoundParameter")
    public void pskCiphersuitesDisabled(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        getPreparedConfig(argumentAccessor, runner);
        TestSiteReport report = this.derivationContainer.getAssociatedSiteReport();
        ConfigurationOptionCompoundDerivation compoundParameter = this.derivationContainer.getDerivation(ConfigurationOptionCompoundDerivation.class);
        DisablePskDerivation disablePskDerivation = compoundParameter.getDerivation(DisablePskDerivation.class);

        if(!disablePskDerivation.getSelectedValue().isOptionSet()){
            return;
        }

        List<AnalyzedProperty> expectedDisabledProperties = Arrays.asList(
                AnalyzedProperty.SUPPORTS_PSK_PLAIN,
                AnalyzedProperty.SUPPORTS_PSK_RSA,
                AnalyzedProperty.SUPPORTS_PSK_DHE,
                AnalyzedProperty.SUPPORTS_PSK_ECDHE
        );

        List<AnalyzedProperty> nonDisabledProperties = new LinkedList<>();
        for(AnalyzedProperty expectedDisabledProperty : expectedDisabledProperties){
            if(report.getResult(expectedDisabledProperty) == TestResult.TRUE){
                // Unexpectedly enabled.
                nonDisabledProperties.add(expectedDisabledProperty);
            }
        }
        assertEquals("Unexpectedly supported features: " + nonDisabledProperties.toString(), 0, nonDisabledProperties.size());
    }


}
