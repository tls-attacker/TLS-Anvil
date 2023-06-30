/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
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

public class AuthTagBitmaskDerivation extends DerivationParameter<Integer> {

    public AuthTagBitmaskDerivation() {
        super(TlsParameterType.AUTH_TAG_BITMASK, Integer.class);
    }

    public AuthTagBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, LegacyDerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        int maxTagLen = 0;
        Set<CipherSuite> cipherSuiteList = context.getFeatureExtractionResult().getCipherSuites();
        if (scope.isTls13Test()) {
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
    public void applyToConfig(Config config, TestContext context) {}

    @Override
    public List<LegacyConditionalConstraint> getDefaultConditionalConstraints(LegacyDerivationScope scope) {
        List<LegacyConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.multipleTagSizesModeled(scope)) {
            condConstraints.add(getMustBeWithinTagSizeConstraint());
        }
        return condConstraints;
    }

    private LegacyConditionalConstraint getMustBeWithinTagSizeConstraint() {
        Set<TlsParameterType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(TlsParameterType.CIPHER_SUITE);

        return new LegacyConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(getType().name(), TlsParameterType.CIPHER_SUITE.name())
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
}
