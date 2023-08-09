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
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class TcpFragmentationDerivation extends TlsDerivationParameter<Boolean> {

    public TcpFragmentationDerivation() {
        super(TlsParameterType.TCP_FRAGMENTATION, Boolean.class);
    }

    public TcpFragmentationDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, Boolean>> getParameterValues(
            AnvilTestTemplate anvilTestTemplate) {
        List<DerivationParameter<TlsAnvilConfig, Boolean>> parameterValues = new LinkedList<>();
        parameterValues.add(new TcpFragmentationDerivation(false));
        parameterValues.add(new TcpFragmentationDerivation(true));
        return parameterValues;
    }

    @Override
    public void applyToConfig(TlsAnvilConfig config, AnvilTestTemplate anvilTestTemplate) {
        if (getSelectedValue() == true) {
            config.getTlsConfig()
                    .getDefaultClientConnection()
                    .setTransportHandlerType(TransportHandlerType.TCP_FRAGMENTATION);
            config.getTlsConfig()
                    .getDefaultServerConnection()
                    .setTransportHandlerType(TransportHandlerType.TCP_FRAGMENTATION);
        }
    }

    @Override
    protected TlsDerivationParameter<Boolean> generateValue(Boolean selectedValue) {
        return new TcpFragmentationDerivation(selectedValue);
    }
}
