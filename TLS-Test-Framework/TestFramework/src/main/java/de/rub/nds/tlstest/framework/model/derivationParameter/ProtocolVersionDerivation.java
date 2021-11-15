package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.List;

/**
 * This class uses byte[] instead of ProtocolVersion for more flexibility
 */
public class ProtocolVersionDerivation extends DerivationParameter<byte[]> {

    public ProtocolVersionDerivation() {
        super(BasicDerivationType.PROTOCOL_VERSION, byte[].class);
    }

    public ProtocolVersionDerivation(byte[] selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }
    
    
    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }

}
