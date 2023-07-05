/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter.mirrored;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/** */
public class MirroredCipherSuiteDerivation extends MirroredDerivationParameter<CipherSuite> {

    public MirroredCipherSuiteDerivation() {
        super(
                TlsParameterType.MIRRORED_CIPHERSUITE,
                TlsParameterType.CIPHER_SUITE,
                CipherSuite.class);
    }

    public MirroredCipherSuiteDerivation(CipherSuite selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, CipherSuite>> getParameterValues(
            DerivationScope scope) {
        List<DerivationParameter<TlsAnvilConfig, CipherSuite>> parameterValues = new LinkedList<>();
        DerivationFactory.getInstance(getMirroredType())
                .getParameterValues(scope)
                .forEach(
                        derivation ->
                                parameterValues.add(
                                        new MirroredCipherSuiteDerivation(
                                                ((CipherSuiteDerivation) (derivation))
                                                        .getSelectedValue())));
        return parameterValues;
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));
        condConstraints.add(
                new ConditionalConstraint(
                        requiredDerivations,
                        ConstraintBuilder.constrain(
                                        getParameterIdentifier().name(),
                                        TlsParameterType.CIPHER_SUITE.name())
                                .by(
                                        (DerivationParameter mirroredCipherSuite,
                                                DerivationParameter cipherSuite) -> {
                                            if (mirroredCipherSuite
                                                    .getSelectedValue()
                                                    .equals(cipherSuite.getSelectedValue())) {
                                                return false;
                                            }
                                            return true;
                                        })));

        return condConstraints;
    }

    @Override
    protected TlsDerivationParameter<CipherSuite> generateValue(CipherSuite selectedValue) {
        return new MirroredCipherSuiteDerivation(selectedValue);
    }
}
