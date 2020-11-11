/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.model;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
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
        for(Object derivation: argumentAccessor.toList()) {
            if(derivation instanceof DerivationParameter) {
                derivations.add((DerivationParameter)derivation);
            } else {
                LOGGER.warn("Found a Test Parameter that is not a DerivationParameter - will be ignored");
            }
        }
    }
    
    public DerivationParameter getDerivation(DerivationType type) {
        for(DerivationParameter listed : derivations) {
            if(listed.getType() == type) {
                return listed;
            }
        }
        LOGGER.warn("Parameter of type " + type + " was not added by model!");
        return null;
    }
    
    public void applyToConfig(Config baseConfig, TestContext context) {
        for(DerivationParameter listed : derivations) {
            listed.applyToConfig(baseConfig, context);
        }
        for(DerivationParameter listed : derivations) {
            listed.postProcessConfig(baseConfig, context);
        }
        System.out.println("Applied " + derivationsToString());
    }
    
    public String derivationsToString() {
        StringJoiner joiner = new StringJoiner(", ");
        for(DerivationParameter derivationParameter: derivations) {
            joiner.add(derivationParameter.toString());
        }
        return joiner.toString();
    }


}
