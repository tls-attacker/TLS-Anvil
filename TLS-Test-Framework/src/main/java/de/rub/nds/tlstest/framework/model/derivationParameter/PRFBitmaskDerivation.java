/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.model.AnvilTestTemplate;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
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
public class PRFBitmaskDerivation extends TlsDerivationParameter<Integer> {

    public PRFBitmaskDerivation() {
        super(TlsParameterType.PRF_BITMASK, Integer.class);
    }

    public PRFBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List getParameterValues(AnvilTestTemplate scope) {
        List<DerivationParameter<TlsAnvilConfig, Integer>> parameterValues = new LinkedList<>();
        if (ConstraintHelper.isTls13Test(scope)) {
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
    public List<ConditionalConstraint> getDefaultConditionalConstraints(AnvilTestTemplate scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        if (ConstraintHelper.isTls13Test(scope)
                && ConstraintHelper.multipleHkdfSizesModeled(scope)) {
            condConstraints.add(getMustBeWithinPRFSizeConstraint());
        }
        return condConstraints;
    }

    private ConditionalConstraint getMustBeWithinPRFSizeConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));

        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getParameterIdentifier().name(),
                                TlsParameterType.CIPHER_SUITE.name())
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

    @Override
    protected TlsDerivationParameter<Integer> generateValue(Integer selectedValue) {
        return new PRFBitmaskDerivation(selectedValue);
    }
}
