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
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class GreaseSigHashDerivation extends TlsDerivationParameter<SignatureAndHashAlgorithm> {

    public GreaseSigHashDerivation() {
        super(TlsParameterType.GREASE_SIG_HASH, SignatureAndHashAlgorithm.class);
    }

    public GreaseSigHashDerivation(SignatureAndHashAlgorithm selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    protected TlsDerivationParameter<SignatureAndHashAlgorithm> generateValue(
            SignatureAndHashAlgorithm selectedValue) {
        return new GreaseSigHashDerivation(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, SignatureAndHashAlgorithm>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, SignatureAndHashAlgorithm>> parameterValues =
                new LinkedList<>();
        for (SignatureAndHashAlgorithm sigHashAlg : SignatureAndHashAlgorithm.values()) {
            if (sigHashAlg.isGrease()) {
                parameterValues.add(new GreaseSigHashDerivation(sigHashAlg));
            }
        }
        return parameterValues;
    }
}
