/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

/**
 * This is only applied to legay Change Cipher Specs used for
 * backwardscompatibility in a TLS 1.3 handshake
 */
public class IncludeChangeCipherSpecDerivation extends DerivationParameter<Boolean> {

    public IncludeChangeCipherSpecDerivation() {
        super(DerivationType.INCLUDE_CHANGE_CIPHER_SPEC, Boolean.class);
    }
    public IncludeChangeCipherSpecDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeChangeCipherSpecDerivation(true));
        parameterValues.add(new IncludeChangeCipherSpecDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setTls13BackwardsCompatibilityMode(getSelectedValue());
    }
}
