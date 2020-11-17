/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/**
 *
 * Holds parameters that represent one set of test derivation.
 */
public class DerivationContainer {

    private static final Logger LOGGER = LogManager.getLogger();
    private List<DerivationParameter> derivations;

    public DerivationContainer(ArgumentsAccessor argumentAccessor) {
        derivations = new LinkedList<>();
        for (Object derivation : argumentAccessor.toList()) {
            if (derivation instanceof DerivationParameter) {
                derivations.add((DerivationParameter) derivation);
            } else {
                LOGGER.warn("Found a Test Parameter that is not a DerivationParameter - will be ignored");
            }
        }
    }
    
    public <T extends DerivationParameter<?>> T getDerivation(Class<T> clazz) {
        for(DerivationParameter listed : derivations) {
            if(clazz.equals(listed.getClass())) {
                return (T)listed;
            }
        }
        return null;
    }

    public DerivationParameter getDerivation(DerivationType type) {
        for (DerivationParameter listed : derivations) {
            if (listed.getType() == type) {
                return listed;
            }
        }
        LOGGER.warn("Parameter of type " + type + " was not added by model!");
        return null;
    }

    public DerivationParameter getChildParameter(DerivationType type) {
        for (DerivationParameter listed : derivations) {
            if (listed.getParent() == type) {
                return listed;
            }
        }
        LOGGER.warn("Child of parameter " + type + " was not added by model!");
        return null;
    }

    public void applyToConfig(Config baseConfig, TestContext context) {
        for (DerivationParameter listed : derivations) {
            listed.applyToConfig(baseConfig, context);
        }
        for (DerivationParameter listed : derivations) {
            listed.postProcessConfig(baseConfig, context);
        }
        System.out.println("Applied " + derivationsToString());
    }

    public String derivationsToString() {
        StringJoiner joiner = new StringJoiner(", ");
        for (DerivationParameter derivationParameter : derivations) {
            joiner.add(derivationParameter.toString());
        }
        return joiner.toString();
    }
    
    public byte[] buildBitmask() {
        for (DerivationParameter listed : derivations) {
            if (listed.getType().isBitmaskDerivation()) {
                return buildBitmask(listed.getType());
            }
        }
        return null;
    }

    public byte[] buildBitmask(DerivationType type) {
        DerivationParameter byteParameter = getDerivation(type);
        DerivationParameter bitParameter = getChildParameter(type);
        
        byte[] constructed = new byte[(Integer)byteParameter.getSelectedValue() + 1];
        constructed[(Integer)byteParameter.getSelectedValue()] = (byte)(1 << (Integer)bitParameter.getSelectedValue());
        return constructed;
    }

}
