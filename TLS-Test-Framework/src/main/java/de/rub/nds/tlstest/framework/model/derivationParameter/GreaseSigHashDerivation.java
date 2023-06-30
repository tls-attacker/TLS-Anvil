/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

public class GreaseSigHashDerivation extends DerivationParameter<SignatureAndHashAlgorithm> {

    public GreaseSigHashDerivation() {
        super(DerivationType.GREASE_SIG_HASH, SignatureAndHashAlgorithm.class);
    }

    public GreaseSigHashDerivation(SignatureAndHashAlgorithm selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        for (SignatureAndHashAlgorithm sigHashAlg : SignatureAndHashAlgorithm.values()) {
            if (sigHashAlg.isGrease()) {
                parameterValues.add(new GreaseSigHashDerivation(sigHashAlg));
            }
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {}
}
