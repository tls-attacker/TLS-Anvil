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
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class MacBitmaskDerivation extends TlsDerivationParameter<Integer> {

    public MacBitmaskDerivation() {
        super(TlsParameterType.MAC_BITMASK, Integer.class);
    }

    public MacBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, Integer>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, Integer>> parameterValues = new LinkedList<>();
        int maxMacLenght = 0;
        for (CipherSuite cipherSuite : context.getFeatureExtractionResult().getCipherSuites()) {
            MacAlgorithm macAlg =
                    AlgorithmResolver.getMacAlgorithm(
                            ConstraintHelper.getTargetVersion(derivationScope), cipherSuite);
            if (macAlg != MacAlgorithm.AEAD
                    && macAlg != MacAlgorithm.NULL
                    && maxMacLenght < macAlg.getSize()) {
                maxMacLenght = macAlg.getSize();
            }
        }

        for (int i = 0; i < maxMacLenght; i++) {
            parameterValues.add(new MacBitmaskDerivation(i));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(TlsAnvilConfig config, DerivationScope derivationScope) {}

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.multipleMacSizesModeled(scope)) {
            condConstraints.add(getMustBeWithinMacSizeConstraint(scope));
        }
        return condConstraints;
    }

    private ConditionalConstraint getMustBeWithinMacSizeConstraint(DerivationScope scope) {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));

        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getParameterIdentifier().name(),
                                TlsParameterType.CIPHER_SUITE.name())
                        .by(
                                (MacBitmaskDerivation macBitmaskDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    int selectedBitmaskBytePosition =
                                            macBitmaskDerivation.getSelectedValue();
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    return AlgorithmResolver.getMacAlgorithm(
                                                            ConstraintHelper.getTargetVersion(
                                                                    scope),
                                                            selectedCipherSuite)
                                                    .getSize()
                                            > selectedBitmaskBytePosition;
                                }));
    }

    @Override
    protected TlsDerivationParameter<Integer> generateValue(Integer selectedValue) {
        return new MacBitmaskDerivation(selectedValue);
    }
}
