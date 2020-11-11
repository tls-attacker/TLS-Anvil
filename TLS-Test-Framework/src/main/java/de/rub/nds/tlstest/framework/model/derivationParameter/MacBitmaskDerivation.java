/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author marcel
 */
public class MacBitmaskDerivation extends DerivationParameter<byte[]>  {

    public MacBitmaskDerivation() {
        super(DerivationType.MAC_BITMASK);
    }
    
    public MacBitmaskDerivation(byte[] selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        byte[][] bitmasks = { new byte[] {0x1},
            new byte[] {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x1}};
        Arrays.stream(bitmasks).forEach(mask -> parameterValues.add(new MacBitmaskDerivation(mask)));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }
    
}
