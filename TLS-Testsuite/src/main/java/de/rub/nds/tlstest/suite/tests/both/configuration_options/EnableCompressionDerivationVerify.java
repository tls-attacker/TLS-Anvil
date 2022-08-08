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


import static org.junit.Assert.assertTrue;

import java.util.LinkedList;
import java.util.List;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
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
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableCompressionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

@Tag("co")
public class EnableCompressionDerivationVerify extends Tls12Test {

    public ConditionEvaluationResult enableCompressionOptionTested() {
        if (ParameterExtensionManager.getInstance().getLoadedExtensions().contains("ConfigurationOptionsExtension")) {
            if (ConfigurationOptionsDerivationManager.getInstance().getAllActivatedCOTypes().contains(ConfigOptionDerivationType.EnableCompression)){
                return ConditionEvaluationResult.enabled("");
            }
            else {
                return ConditionEvaluationResult.disabled("The EnableCompression option is not tested.");
            }
        } else {
            return ConditionEvaluationResult.disabled("Configuration options are not tested.");
        }
    }

    @TlsTest(description = "The configuration option EnableCompression enables compression.")
    @MethodCondition(method = "enableCompressionOptionTested")
    @ModelFromScope(baseModel = ModelType.EMPTY)
    @ScopeExtensions("ConfigOptionDerivationType.ConfigurationOptionCompoundParameter")
    public void compressionDisabledByOption(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        getPreparedConfig(argumentAccessor, runner);
        TestSiteReport report = this.derivationContainer.getAssociatedSiteReport();
        ConfigurationOptionCompoundDerivation compoundParameter = this.derivationContainer.getDerivation(ConfigurationOptionCompoundDerivation.class);
        EnableCompressionDerivation enableCompressionDerivation = compoundParameter.getDerivation(EnableCompressionDerivation.class);

        if(!enableCompressionDerivation.getSelectedValue().isOptionSet()){
            return;
        }
        List<CompressionMethod> supportedNonNullCompressionMethods = new LinkedList<>();
        List<CompressionMethod> supportedCompressionMethods = report.getSupportedCompressionMethods();
        if(supportedCompressionMethods == null){
            // Currently not scanned in client tests
            return;
        }

        for(CompressionMethod compressionMethod : report.getSupportedCompressionMethods()){
            if(compressionMethod != CompressionMethod.NULL){
                supportedNonNullCompressionMethods.add(compressionMethod);
            }
        }

        assertTrue("No compression method was enabled using the EnableCompressionDerivation.", supportedNonNullCompressionMethods.size() > 0);
    }


}
