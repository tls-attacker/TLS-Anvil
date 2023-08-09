/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.model.AnvilTestTemplate;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.List;

/** */
public class ExtensionDerivation extends TlsDerivationParameter<ExtensionType> {

    public ExtensionDerivation() {
        super(TlsParameterType.EXTENSION, ExtensionType.class);
    }

    public ExtensionDerivation(ExtensionType selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    protected TlsDerivationParameter<ExtensionType> generateValue(ExtensionType selectedValue) {
        return new ExtensionDerivation(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, ExtensionType>> getParameterValues(
            AnvilTestTemplate anvilTestTemplate) {
        // currently this is only used for explicitly listed (unrequested) extensions
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
