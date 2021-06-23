/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

public class MaxFragmentLengthDerivation extends DerivationParameter<MaxFragmentLength> {

    public MaxFragmentLengthDerivation() {
        super(DerivationType.MAX_FRAGMENT_LENGTH, MaxFragmentLength.class);
    }

    public MaxFragmentLengthDerivation(MaxFragmentLength selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();

        if(context.getSiteReport().getSupportedExtensions().contains(ExtensionType.MAX_FRAGMENT_LENGTH)){
            for(MaxFragmentLength maxFragmentLength : MaxFragmentLength.values()){
                parameterValues.add(new MaxFragmentLengthDerivation(maxFragmentLength));
            }
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        if (getSelectedValue() != null) {
            config.setMaxFragmentLength(getSelectedValue());
            config.setAddMaxFragmentLengthExtension(true);
        }
    }

}


