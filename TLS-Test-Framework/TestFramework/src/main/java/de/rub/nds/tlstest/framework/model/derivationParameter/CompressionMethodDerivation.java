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
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;


public class CompressionMethodDerivation extends DerivationParameter<CompressionMethod> {

    public CompressionMethodDerivation() {
        super(DerivationType.COMPRESSION_METHOD, CompressionMethod.class);
    }
    
    public CompressionMethodDerivation(CompressionMethod selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }
    
    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        for(CompressionMethod compressionMethod : CompressionMethod.values()) {
            parameterValues.add(new CompressionMethodDerivation(compressionMethod));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        //current tests only apply the compression method explicitly using
        //modifiable variables
    }

}
