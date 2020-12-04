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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
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

/**
 * Determines the bytes that affect the bitmask used to alter the output of the
 * PRF (TLS 1.2) or HKDF (TLS 1.3)
 */
public class PRFBitmaskDerivation extends DerivationParameter<Integer> {

    public PRFBitmaskDerivation() {
        super(DerivationType.PRF_BITMASK, Integer.class);
    }

    public PRFBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        if (scope.isTls13Test()) {
            int maxHkdfSize = 0;
            for (CipherSuite cipherSuite : context.getSiteReport().getSupportedTls13CipherSuites()) {
                int hkdfSize = AlgorithmResolver.getHKDFAlgorithm(cipherSuite).getMacAlgorithm().getSize();
                if (hkdfSize > maxHkdfSize) {
                    maxHkdfSize = hkdfSize;
                }
            }
            for (int i = 0; i < maxHkdfSize; i++) {
                parameterValues.add(new PRFBitmaskDerivation(i));
            }
        } else {
            for (int i = 0; i < HandshakeByteLength.VERIFY_DATA; i++) {
                parameterValues.add(new PRFBitmaskDerivation(i));
            }
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }

    @Override
    public List<ConditionalConstraint> getConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        if (scope.isTls13Test() && ConstraintHelper.multipleHkdfSizesModeled(scope)) {
            Set<DerivationType> requiredDerivations = new HashSet<>();
            requiredDerivations.add(DerivationType.CIPHERSUITE);

            //selected byte must be within tag size
            condConstraints.add(new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name()).by((DerivationParameter bytePosParam, DerivationParameter cipherSuite) -> {
                int selectedPos = (Integer) bytePosParam.getSelectedValue();
                CipherSuiteDerivation cipherDev = (CipherSuiteDerivation) cipherSuite;
                return AlgorithmResolver.getHKDFAlgorithm(cipherDev.getSelectedValue()).getMacAlgorithm().getSize() > selectedPos;
            })));
        }
        return condConstraints;
    }

}
