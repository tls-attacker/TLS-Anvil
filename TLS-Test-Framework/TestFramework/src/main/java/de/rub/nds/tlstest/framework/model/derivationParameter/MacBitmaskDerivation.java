/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class MacBitmaskDerivation extends DerivationParameter<Integer> {

    public MacBitmaskDerivation() {
        super(DerivationType.MAC_BITMASK, Integer.class);
    }

    public MacBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        int maxMacLenght = 0;
        for (CipherSuite cipherSuite : context.getSiteReport().getCipherSuites()) {
            MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(scope.getTargetVersion(), cipherSuite);
            if (macAlg != MacAlgorithm.AEAD && macAlg != MacAlgorithm.NULL && maxMacLenght < macAlg.getSize()) {
                maxMacLenght = macAlg.getSize();
            }
        }

        for (int i = 0; i < maxMacLenght; i++) {
            parameterValues.add(new MacBitmaskDerivation(i));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.multipleMacSizesModeled(scope)) {
            condConstraints.add(getMustBeWithinMacSizeConstraint(scope));
        }
        return condConstraints;
    }

    private ConditionalConstraint getMustBeWithinMacSizeConstraint(DerivationScope scope) {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);

        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name()).by((MacBitmaskDerivation macBitmaskDerivation, CipherSuiteDerivation cipherSuiteDerivation) -> {
            int selectedBitmaskBytePosition = macBitmaskDerivation.getSelectedValue();
            CipherSuite selectedCipherSuite = cipherSuiteDerivation.getSelectedValue();
            
            return AlgorithmResolver.getMacAlgorithm(scope.getTargetVersion(), selectedCipherSuite).getSize() > selectedBitmaskBytePosition;
        }));
    }

}
