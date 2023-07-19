/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class CipherSuiteDerivation extends TlsDerivationParameter<CipherSuite> {

    public CipherSuiteDerivation() {
        super(TlsParameterType.CIPHER_SUITE, CipherSuite.class);
    }

    public CipherSuiteDerivation(CipherSuite selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public void applyToConfig(TlsAnvilConfig config, DerivationScope derivationScope) {
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            config.getTlsConfig().setDefaultClientSupportedCipherSuites(getSelectedValue());
        } else {
            config.getTlsConfig().setDefaultServerSupportedCipherSuites(getSelectedValue());
        }
        config.getTlsConfig().setDefaultSelectedCipherSuite(getSelectedValue());
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, CipherSuite>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, CipherSuite>> parameterValues = new LinkedList<>();
        Set<CipherSuite> cipherSuiteList = context.getFeatureExtractionResult().getCipherSuites();
        cipherSuiteList.addAll(
                context.getFeatureExtractionResult().getSupportedTls13CipherSuites());
        for (CipherSuite cipherSuite : cipherSuiteList) {
            if (ConstraintHelper.getKeyExchangeRequirements(derivationScope)
                    .compatibleWithCiphersuite(cipherSuite)) {
                parameterValues.add(new CipherSuiteDerivation(cipherSuite));
            }
        }

        return parameterValues;
    }

    @Override
    protected TlsDerivationParameter<CipherSuite> generateValue(CipherSuite selectedValue) {
        return new CipherSuiteDerivation(selectedValue);
    }
}
