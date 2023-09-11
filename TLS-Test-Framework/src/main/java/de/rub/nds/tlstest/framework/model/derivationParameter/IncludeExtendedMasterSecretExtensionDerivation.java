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
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

/** */
public class IncludeExtendedMasterSecretExtensionDerivation
        extends TlsDerivationParameter<Boolean> {

    public IncludeExtendedMasterSecretExtensionDerivation() {
        super(TlsParameterType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION, Boolean.class);
    }

    public IncludeExtendedMasterSecretExtensionDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<Config, Boolean>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<Config, Boolean>> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeExtendedMasterSecretExtensionDerivation(true));
        parameterValues.add(new IncludeExtendedMasterSecretExtensionDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, DerivationScope derivationScope) {
        config.setAddExtendedMasterSecretExtension(getSelectedValue());
    }

    @Override
    protected TlsDerivationParameter<Boolean> generateValue(Boolean selectedValue) {
        return new IncludeExtendedMasterSecretExtensionDerivation(selectedValue);
    }
}
