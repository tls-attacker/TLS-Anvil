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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class AuthTagBitmaskDerivation extends TlsDerivationParameter<Integer> {

    public AuthTagBitmaskDerivation() {
        super(TlsParameterType.AUTH_TAG_BITMASK, Integer.class);
    }

    public AuthTagBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(
            DerivationScope derivationScope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.multipleTagSizesModeled(derivationScope)) {
            condConstraints.add(getMustBeWithinTagSizeConstraint());
        }
        return condConstraints;
    }

    private ConditionalConstraint getMustBeWithinTagSizeConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));

        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getParameterIdentifier().name(),
                                TlsParameterType.CIPHER_SUITE.name())
                        .by(
                                (AuthTagBitmaskDerivation authTagBitmaskDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    int selectedBitmaskBytePosition =
                                            authTagBitmaskDerivation.getSelectedValue();
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    return getAuthTagLen(selectedCipherSuite)
                                            > selectedBitmaskBytePosition;
                                }));
    }

    // TODO: integrate into AlgorithmResolver?
    private int getAuthTagLen(CipherSuite cipherSuite) {
        if (cipherSuite.name().contains("CCM_8")) {
            return 8;
        }
        return 16;
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, Integer>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, Integer>> parameterValues = new LinkedList<>();
        int maxTagLen = 0;
        Set<CipherSuite> cipherSuiteList = context.getFeatureExtractionResult().getCipherSuites();
        if (ConstraintHelper.isTls13Test(derivationScope)) {
            cipherSuiteList = context.getFeatureExtractionResult().getSupportedTls13CipherSuites();
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
    protected TlsDerivationParameter<Integer> generateValue(Integer selectedValue) {
        return new AuthTagBitmaskDerivation(selectedValue);
    }
}
