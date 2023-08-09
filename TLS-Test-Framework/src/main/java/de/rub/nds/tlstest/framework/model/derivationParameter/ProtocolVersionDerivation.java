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
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.List;

/** This class uses byte[] instead of ProtocolVersion for more flexibility */
public class ProtocolVersionDerivation extends TlsDerivationParameter<byte[]> {

    public ProtocolVersionDerivation() {
        super(TlsParameterType.PROTOCOL_VERSION, byte[].class);
    }

    public ProtocolVersionDerivation(byte[] selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, byte[]>> getParameterValues(
            AnvilTestTemplate anvilTestTemplate) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected TlsDerivationParameter<byte[]> generateValue(byte[] selectedValue) {
        return new ProtocolVersionDerivation(selectedValue);
    }
}
