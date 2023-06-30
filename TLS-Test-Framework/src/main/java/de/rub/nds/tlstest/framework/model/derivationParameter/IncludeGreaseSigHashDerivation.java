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
import de.rub.nds.tlstest.framework.model.LegacyDerivationScope;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/** */
public class IncludeGreaseSigHashDerivation extends DerivationParameter<Boolean> {

    public IncludeGreaseSigHashDerivation() {
        super(TlsParameterType.INCLUDE_GREASE_SIG_HASH_ALGORITHMS, Boolean.class);
    }

    public IncludeGreaseSigHashDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, LegacyDerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeGreaseSigHashDerivation(true));
        parameterValues.add(new IncludeGreaseSigHashDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {}

    @Override
    public void postProcessConfig(Config config, TestContext context) {
        if (getSelectedValue()) {
            Arrays.asList(SignatureAndHashAlgorithm.values()).stream()
                    .filter(algorithm -> algorithm.isGrease())
                    .forEach(
                            greaseAlgorithm ->
                                    config.getDefaultClientSupportedSignatureAndHashAlgorithms()
                                            .add(greaseAlgorithm));
        }
    }
}
