/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.List;

/** Used to select a handshake message to apply modifications to. */
public class ChosenHandshakeMessageDerivation extends DerivationParameter<HandshakeMessageType> {

    public ChosenHandshakeMessageDerivation() {
        super(DerivationType.CHOSEN_HANDSHAKE_MSG, HandshakeMessageType.class);
    }

    public ChosenHandshakeMessageDerivation(HandshakeMessageType selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, DerivationScope scope) {
        // currently, automatic value selection does not make sense here
        throw new UnsupportedOperationException(
                "Not supported yet."); // To change body of generated methods, choose Tools |
        // Templates.
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        // currently, automatic value selection does not make sense here
    }
}
