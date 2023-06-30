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
import de.rub.nds.tlsattacker.core.constants.CipherType;
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

public class CipherTextBitmaskDerivation extends DerivationParameter<Integer> {

    public CipherTextBitmaskDerivation() {
        super(TlsParameterType.CIPHERTEXT_BITMASK, Integer.class);
    }

    public CipherTextBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, LegacyDerivationScope scope) {
        int maxCipherTextByteLen = 0;
        Set<CipherSuite> cipherSuiteList = context.getFeatureExtractionResult().getCipherSuites();
        if (scope.isTls13Test()) {
            cipherSuiteList = context.getFeatureExtractionResult().getSupportedTls13CipherSuites();
        }
        for (CipherSuite cipherSuite : cipherSuiteList) {
            if (AlgorithmResolver.getCipher(cipherSuite).getBlocksize() > maxCipherTextByteLen) {
                maxCipherTextByteLen = AlgorithmResolver.getCipher(cipherSuite).getBlocksize();
            }
        }

        List<DerivationParameter> parameterValues = new LinkedList<>();
        for (int i = 0; i < maxCipherTextByteLen; i++) {
            parameterValues.add(new CipherTextBitmaskDerivation(i));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {}

    @Override
    public List<LegacyConditionalConstraint> getDefaultConditionalConstraints(LegacyDerivationScope scope) {
        List<LegacyConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.multipleBlocksizesModeled(scope)) {
            condConstraints.add(getMustBeWithinBlocksizeConstraint());
        }

        if (ConstraintHelper.unpaddedCipherSuitesModeled(scope)) {
            condConstraints.add(getMustBeWithinCiphertextSizeConstraint(scope));
        }
        return condConstraints;
    }

    private LegacyConditionalConstraint getMustBeWithinBlocksizeConstraint() {
        Set<TlsParameterType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(TlsParameterType.CIPHER_SUITE);

        return new LegacyConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(TlsParameterType.CIPHERTEXT_BITMASK.name(),
                                TlsParameterType.CIPHER_SUITE.name())
                        .by(
                                (DerivationParameter bytePos, DerivationParameter cipherSuite) -> {
                                    int chosenBytePos = (Integer) bytePos.getSelectedValue();
                                    CipherSuiteDerivation cipherDev =
                                            (CipherSuiteDerivation) cipherSuite;
                                    return AlgorithmResolver.getCipher(cipherDev.getSelectedValue())
                                                    .getBlocksize()
                                            > chosenBytePos;
                                }));
    }

    private LegacyConditionalConstraint getMustBeWithinCiphertextSizeConstraint(LegacyDerivationScope scope) {
        Set<TlsParameterType> requiredDerivationsCiphertext = new HashSet<>();
        requiredDerivationsCiphertext.add(TlsParameterType.CIPHER_SUITE);
        requiredDerivationsCiphertext.add(TlsParameterType.APP_MSG_LENGHT);

        // ensure that the selected byte is within ciphertext size (for non-padded)
        return new LegacyConditionalConstraint(
                requiredDerivationsCiphertext,
                ConstraintBuilder.constrain(TlsParameterType.CIPHERTEXT_BITMASK.name(),
                                TlsParameterType.CIPHER_SUITE.name(),
                                TlsParameterType.APP_MSG_LENGHT.name())
                        .by(
                                (CipherTextBitmaskDerivation cipherTextBitmaskDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation,
                                        AppMsgLengthDerivation appMsgLenParam) -> {
                                    int selectedBitmaskBytePosition =
                                            cipherTextBitmaskDerivation.getSelectedValue();
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();
                                    int selectedAppMsgLength = appMsgLenParam.getSelectedValue();

                                    if (!selectedCipherSuite.isUsingPadding(
                                                    scope.getTargetVersion())
                                            || AlgorithmResolver.getCipherType(selectedCipherSuite)
                                                    == CipherType.AEAD) {
                                        return selectedAppMsgLength > selectedBitmaskBytePosition;
                                    }
                                    return true;
                                }));
    }
}
