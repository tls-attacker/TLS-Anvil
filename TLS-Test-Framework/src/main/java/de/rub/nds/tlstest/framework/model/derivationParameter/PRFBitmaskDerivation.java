/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.LegacyDerivationScope;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.LegacyConditionalConstraint;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Determines the bytes that affect the bitmask used to alter the output of the PRF (TLS 1.2) or
 * HKDF (TLS 1.3)
 */
public class PRFBitmaskDerivation extends DerivationParameter<Integer> {

    public PRFBitmaskDerivation() {
        super(TlsParameterType.PRF_BITMASK, Integer.class);
    }

    public PRFBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List getParameterValues(TestContext context, LegacyDerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        if (scope.isTls13Test()) {
            int maxHkdfSize = 0;
            for (CipherSuite cipherSuite :
                    context.getFeatureExtractionResult().getSupportedTls13CipherSuites()) {
                int hkdfSize =
                        AlgorithmResolver.getHKDFAlgorithm(cipherSuite).getMacAlgorithm().getSize();
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
    public void applyToConfig(Config config, TestContext context) {}

    @Override
    public List<LegacyConditionalConstraint> getDefaultConditionalConstraints(LegacyDerivationScope scope) {
        List<LegacyConditionalConstraint> condConstraints = new LinkedList<>();
        if (scope.isTls13Test() && ConstraintHelper.multipleHkdfSizesModeled(scope)) {
            condConstraints.add(getMustBeWithinPRFSizeConstraint());
        }
        return condConstraints;
    }

    private LegacyConditionalConstraint getMustBeWithinPRFSizeConstraint() {
        Set<TlsParameterType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(TlsParameterType.CIPHER_SUITE);

        return new LegacyConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(getType().name(), TlsParameterType.CIPHER_SUITE.name())
                        .by(
                                (PRFBitmaskDerivation prfBitmaskDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    int selectedBitmaskBytePosition =
                                            prfBitmaskDerivation.getSelectedValue();
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    return AlgorithmResolver.getHKDFAlgorithm(selectedCipherSuite)
                                                    .getMacAlgorithm()
                                                    .getSize()
                                            > selectedBitmaskBytePosition;
                                }));
    }
}
