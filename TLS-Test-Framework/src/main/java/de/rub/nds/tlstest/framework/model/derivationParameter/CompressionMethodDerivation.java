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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class CompressionMethodDerivation extends TlsDerivationParameter<CompressionMethod> {

    public CompressionMethodDerivation() {
        super(TlsParameterType.COMPRESSION_METHOD, CompressionMethod.class);
    }

    public CompressionMethodDerivation(CompressionMethod selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    protected TlsDerivationParameter<CompressionMethod> generateValue(
            CompressionMethod selectedValue) {
        return new CompressionMethodDerivation(selectedValue);
    }

    @Override
    public List<DerivationParameter<Config, CompressionMethod>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<Config, CompressionMethod>> parameterValues = new LinkedList<>();
        for (CompressionMethod compressionMethod : CompressionMethod.values()) {
            parameterValues.add(new CompressionMethodDerivation(compressionMethod));
        }
        return parameterValues;
    }
}
