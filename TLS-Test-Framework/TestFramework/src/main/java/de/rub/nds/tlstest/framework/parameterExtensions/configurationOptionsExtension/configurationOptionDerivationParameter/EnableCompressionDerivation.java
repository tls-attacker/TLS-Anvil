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

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xbill.DNS.Compression;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class EnableCompressionDerivation extends ConfigurationOptionDerivationParameter{
    private static final Logger LOGGER = LogManager.getLogger();

    public EnableCompressionDerivation(){
        super(ConfigOptionDerivationType.EnableCompression);
    }

    public EnableCompressionDerivation(ConfigurationOptionValue selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getAllParameterValues(TestContext context) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new EnableCompressionDerivation(new ConfigurationOptionValue(false)));
        parameterValues.add(new EnableCompressionDerivation(new ConfigurationOptionValue(true)));

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
        List<CompressionMethod> supportedNonNullCompressionMethods = new LinkedList<>();
        for(CompressionMethod compressionMethod : report.getSupportedCompressionMethods()){
            if(compressionMethod != CompressionMethod.NULL){
                supportedNonNullCompressionMethods.add(compressionMethod);
            }
        }

        if(supportedNonNullCompressionMethods.size() == 0){
            LOGGER.warn("No compression method was enabled using the EnableCompressionDerivation.");
            return false;
        }

        return true;
    }
}
