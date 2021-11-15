/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class AuthTagBitmaskDerivation extends DerivationParameter<Integer> {

    public AuthTagBitmaskDerivation() {
        super(BasicDerivationType.AUTH_TAG_BITMASK, Integer.class);
    }

    public AuthTagBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        int maxTagLen = 0;
        Set<CipherSuite> cipherSuiteList = context.getSiteReport().getCipherSuites();
        if (scope.isTls13Test()) {
            cipherSuiteList = context.getSiteReport().getSupportedTls13CipherSuites();
        }
        for (CipherSuite cipherSuite : cipherSuiteList) {
            if (cipherSuite.isAEAD()) {
                if (maxTagLen < getAuthTagLen(cipherSuite)) {
                    maxTagLen = getAuthTagLen(cipherSuite);
                }
            }
        }

        for (int i = 0; i < maxTagLen; i++) {
            parameterValues.add(new AuthTagBitmaskDerivation(i));
        }

        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.multipleTagSizesModeled(scope)) {
            condConstraints.add(getMustBeWithinTagSizeConstraint());
        }
        return condConstraints;
    }

    private ConditionalConstraint getMustBeWithinTagSizeConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(BasicDerivationType.CIPHERSUITE);

        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().toString(), BasicDerivationType.CIPHERSUITE.name()).by((AuthTagBitmaskDerivation authTagBitmaskDerivation, CipherSuiteDerivation cipherSuiteDerivation) -> {
            int selectedBitmaskBytePosition = authTagBitmaskDerivation.getSelectedValue();
            CipherSuite selectedCipherSuite = cipherSuiteDerivation.getSelectedValue();
            
            return getAuthTagLen(selectedCipherSuite) > selectedBitmaskBytePosition;
        }));
    }

    //TODO: integrate into AlgorithmResolver?
    private int getAuthTagLen(CipherSuite cipherSuite) {
        if (cipherSuite.name().contains("CCM_8")) {
            return 8;
        }
        return 16;
    }

}
