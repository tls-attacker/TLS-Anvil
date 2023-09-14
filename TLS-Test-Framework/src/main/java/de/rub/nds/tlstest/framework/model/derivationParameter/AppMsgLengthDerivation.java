/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class AppMsgLengthDerivation extends TlsDerivationParameter<Integer> {

    private static final char ASCII_LETTER = 'A';
    private static final int UNPADDED_MIN_LENGTH = 16;

    public AppMsgLengthDerivation() {
        super(TlsParameterType.APP_MSG_LENGHT, Integer.class);
    }

    public AppMsgLengthDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    public static char getAsciiLetter() {
        return ASCII_LETTER;
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.multipleBlocksizesModeled(scope)) {
            condConstraints.add(getMustBeWithinBlocksizeConstraint());
        }
        return condConstraints;
    }

    private ConditionalConstraint getMustBeWithinBlocksizeConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));

        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                TlsParameterType.APP_MSG_LENGHT.name(),
                                TlsParameterType.CIPHER_SUITE.name())
                        .by(
                                (AppMsgLengthDerivation appMsgLengthDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    int selectedAppMsgLength =
                                            appMsgLengthDerivation.getSelectedValue();
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    if (AlgorithmResolver.getCipherType(selectedCipherSuite)
                                            == CipherType.BLOCK) {
                                        return AlgorithmResolver.getCipher(selectedCipherSuite)
                                                        .getBlocksize()
                                                >= selectedAppMsgLength;
                                    }
                                    return true;
                                }));
    }

    @Override
    public void applyToConfig(Config config, DerivationScope derivationScope) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < getSelectedValue(); i++) {
            builder.append(ASCII_LETTER);
        }
        config.setDefaultApplicationMessageData(builder.toString());
    }

    @Override
    public List<DerivationParameter<Config, Integer>> getParameterValues(
            DerivationScope derivationScope) {
        int maxCipherTextByteLen = 0;
        Set<CipherSuite> cipherSuiteList = context.getFeatureExtractionResult().getCipherSuites();
        if (ConstraintHelper.isTls13Test(derivationScope)) {
            cipherSuiteList = context.getFeatureExtractionResult().getSupportedTls13CipherSuites();
        }
        for (CipherSuite cipherSuite : cipherSuiteList) {
            if (AlgorithmResolver.getCipher(cipherSuite).getBlocksize() > maxCipherTextByteLen) {
                maxCipherTextByteLen = AlgorithmResolver.getCipher(cipherSuite).getBlocksize();
            }
        }

        if (maxCipherTextByteLen == 0) {
            maxCipherTextByteLen = UNPADDED_MIN_LENGTH;
        }

        List<DerivationParameter<Config, Integer>> parameterValues = new LinkedList<>();
        for (int i = 1; i <= maxCipherTextByteLen; i++) {
            parameterValues.add(new AppMsgLengthDerivation(i));
        }
        return parameterValues;
    }

    @Override
    protected TlsDerivationParameter<Integer> generateValue(Integer selectedValue) {
        return new AppMsgLengthDerivation(selectedValue);
    }
}
