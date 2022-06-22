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
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class DisableNextProtocolNegotiationExtensionDerivation extends ConfigurationOptionDerivationParameter {
    public DisableNextProtocolNegotiationExtensionDerivation(){
        super(ConfigOptionDerivationType.DisableNextProtocolNegotiationExtension);
    }

    public DisableNextProtocolNegotiationExtensionDerivation(ConfigurationOptionValue selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getAllParameterValues(TestContext context) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new DisableNextProtocolNegotiationExtensionDerivation(new ConfigurationOptionValue(false)));
        parameterValues.add(new DisableNextProtocolNegotiationExtensionDerivation(new ConfigurationOptionValue(true)));

        return parameterValues;
    }

    @Override
    public ConfigurationOptionValue getMaxFeatureValue() {
        return new ConfigurationOptionValue(false);
    }

    @Override
    public boolean validateExpectedBehavior(Set<ConfigurationOptionDerivationParameter> setup, TestSiteReport report){
        // Next protocol negotiation extension not yet in tls attacker
        return true;
    }
}
