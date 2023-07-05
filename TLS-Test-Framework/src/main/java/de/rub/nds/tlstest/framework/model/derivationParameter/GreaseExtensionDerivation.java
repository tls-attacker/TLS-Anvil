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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class GreaseExtensionDerivation extends TlsDerivationParameter<ExtensionType> {

    public GreaseExtensionDerivation() {
        super(TlsParameterType.GREASE_EXTENSION, ExtensionType.class);
    }

    public GreaseExtensionDerivation(ExtensionType selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    protected TlsDerivationParameter<ExtensionType> generateValue(ExtensionType selectedValue) {
        return new GreaseExtensionDerivation(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, ExtensionType>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, ExtensionType>> parameterValues =
                new LinkedList<>();
        for (ExtensionType extType : ExtensionType.values()) {
            if (extType.isGrease()) {
                parameterValues.add(new GreaseExtensionDerivation(extType));
            }
        }
        return parameterValues;
    }
}
