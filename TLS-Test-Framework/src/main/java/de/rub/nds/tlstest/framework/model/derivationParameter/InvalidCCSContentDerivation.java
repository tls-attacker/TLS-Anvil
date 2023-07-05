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

public class InvalidCCSContentDerivation extends TlsDerivationParameter<byte[]> {

    public InvalidCCSContentDerivation() {
        super(TlsParameterType.INVALID_CCS_CONTENT, byte[].class);
    }

    public InvalidCCSContentDerivation(byte[] selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, byte[]>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, byte[]>> parameterValues = new LinkedList<>();
        parameterValues.add(new InvalidCCSContentDerivation(new byte[] {125}));
        parameterValues.add(new InvalidCCSContentDerivation(new byte[] {1, 1}));
        parameterValues.add(new InvalidCCSContentDerivation(new byte[] {1, 2}));
        parameterValues.add(new InvalidCCSContentDerivation(new byte[] {125, 1}));
        return parameterValues;
    }

    @Override
    protected TlsDerivationParameter<byte[]> generateValue(byte[] selectedValue) {
        return new InvalidCCSContentDerivation(selectedValue);
    }
}
