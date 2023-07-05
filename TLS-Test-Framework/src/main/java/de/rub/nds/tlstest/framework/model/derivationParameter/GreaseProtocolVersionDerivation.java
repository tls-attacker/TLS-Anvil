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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class GreaseProtocolVersionDerivation extends TlsDerivationParameter<ProtocolVersion> {

    public GreaseProtocolVersionDerivation() {
        super(TlsParameterType.GREASE_PROTOCOL_VERSION, ProtocolVersion.class);
    }

    public GreaseProtocolVersionDerivation(ProtocolVersion selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    protected TlsDerivationParameter<ProtocolVersion> generateValue(ProtocolVersion selectedValue) {
        return new GreaseProtocolVersionDerivation(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, ProtocolVersion>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, ProtocolVersion>> parameterValues =
                new LinkedList<>();
        for (ProtocolVersion version : ProtocolVersion.values()) {
            if (version.isGrease()) {
                parameterValues.add(new GreaseProtocolVersionDerivation(version));
            }
        }
        return parameterValues;
    }
}
