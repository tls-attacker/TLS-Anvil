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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.List;

/** Used to select a handshake message to apply modifications to. */
public class ChosenHandshakeMessageDerivation extends TlsDerivationParameter<HandshakeMessageType> {

    public ChosenHandshakeMessageDerivation() {
        super(TlsParameterType.CHOSEN_HANDSHAKE_MSG, HandshakeMessageType.class);
    }

    public ChosenHandshakeMessageDerivation(HandshakeMessageType selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<Config, HandshakeMessageType>> getParameterValues(
            AnvilTestTemplate anvilTestTemplate) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected TlsDerivationParameter<HandshakeMessageType> generateValue(
            HandshakeMessageType selectedValue) {
        return new ChosenHandshakeMessageDerivation(selectedValue);
    }
}
