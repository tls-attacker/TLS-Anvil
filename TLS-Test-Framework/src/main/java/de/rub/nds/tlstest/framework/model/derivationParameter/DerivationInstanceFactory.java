/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlstest.framework.model.DerivationType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author marcel
 */
public class DerivationInstanceFactory {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    public static DerivationParameter getInstance(DerivationType type) {
        switch(type) {
            case CIPHERSUITE:
                return new CipherSuiteDerivation();
            case MAC_BITMASK:
                return new MacBitmaskDerivation();
            case ALERT:
                return new AlertDerivation();
            case NAMED_GROUP:
                return new NamedGroupDerivation();
            default:
                throw new UnsupportedOperationException("Derivation Type not implemented");
        }
    }
}
