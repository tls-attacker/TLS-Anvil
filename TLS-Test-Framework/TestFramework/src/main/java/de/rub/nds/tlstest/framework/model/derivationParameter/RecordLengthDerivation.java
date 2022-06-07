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

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

public class RecordLengthDerivation extends DerivationParameter<Integer>  {

    public RecordLengthDerivation() {
        super(DerivationType.RECORD_LENGTH, Integer.class);
    }
    
    public RecordLengthDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }
    
    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();

        if (context.getSiteReport().getResult(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION) == TestResults.TRUE) {
            parameterValues.add(new RecordLengthDerivation(50));
            parameterValues.add(new RecordLengthDerivation(111));
            parameterValues.add(new RecordLengthDerivation(1));
        }
        parameterValues.add(new RecordLengthDerivation(16384));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setDefaultMaxRecordData(getSelectedValue());
    }
    
}
