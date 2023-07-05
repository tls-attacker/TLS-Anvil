/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class BitPositionDerivation extends TlsDerivationParameter<Integer> {

    public BitPositionDerivation() {
        super(TlsParameterType.BIT_POSITION, Integer.class);
    }

    public BitPositionDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, Integer>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, Integer>> parameterValues = new LinkedList<>();
        for (int i = 0; i < 8; i++) {
            parameterValues.add(new BitPositionDerivation(i));
        }
        return parameterValues;
    }

    @Override
    protected TlsDerivationParameter<Integer> generateValue(Integer selectedValue) {
        return new BitPositionDerivation(selectedValue);
    }
}
