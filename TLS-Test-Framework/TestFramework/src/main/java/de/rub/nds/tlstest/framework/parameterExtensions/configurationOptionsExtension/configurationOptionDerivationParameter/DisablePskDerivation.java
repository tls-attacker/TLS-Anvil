/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter;

import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedPropertyCategory;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Disables PSK cipher suites
 */
public class DisablePskDerivation extends ConfigurationOptionDerivationParameter {
    private static final Logger LOGGER = LogManager.getLogger();

    public DisablePskDerivation(){
        super(ConfigOptionDerivationType.DisablePsk);
    }

    public DisablePskDerivation(ConfigurationOptionValue selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getAllParameterValues(TestContext context) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new DisablePskDerivation(new ConfigurationOptionValue(false)));
        parameterValues.add(new DisablePskDerivation(new ConfigurationOptionValue(true)));

        return parameterValues;
    }

    @Override
    public ConfigurationOptionValue getMaxFeatureValue() {
        return new ConfigurationOptionValue(false);
    }

    @Override
    public boolean validateExpectedBehavior(Set<ConfigurationOptionDerivationParameter> setup, TestSiteReport report){
        // If this option is not set, we can't make expectations
        if(!getSelectedValue().isOptionSet()){
            return true;
        }

        List<AnalyzedProperty> expectedDisabledProperties = Arrays.asList(
                AnalyzedProperty.SUPPORTS_PSK_PLAIN,
                AnalyzedProperty.SUPPORTS_PSK_RSA,
                AnalyzedProperty.SUPPORTS_PSK_DHE,
                AnalyzedProperty.SUPPORTS_PSK_ECDHE
        );

        boolean allValid = true;
        for(AnalyzedProperty expectedDisabledProperty : expectedDisabledProperties){
            if(report.getResult(expectedDisabledProperty) == TestResult.TRUE){
                // Unexpectedly disabled.
                LOGGER.warn("PSK cipher suites should be disabled, but feature '{}' is enabled.", expectedDisabledProperty);
                allValid = false;
            }
        }
        return allValid;


    }
}
