/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.LegacyDerivationScope;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

/** Can be used when ever ProtocolMessageType is needed - eg. RecordContentType */
public class ProtocolMessageTypeDerivation extends DerivationParameter<ProtocolMessageType> {

    public ProtocolMessageTypeDerivation() {
        super(TlsParameterType.PROTOCOL_MESSAGE_TYPE, ProtocolMessageType.class);
    }

    public ProtocolMessageTypeDerivation(ProtocolMessageType selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, LegacyDerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        for (ProtocolMessageType messageType : ProtocolMessageType.values()) {
            parameterValues.add(new ProtocolMessageTypeDerivation(messageType));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {}
}
