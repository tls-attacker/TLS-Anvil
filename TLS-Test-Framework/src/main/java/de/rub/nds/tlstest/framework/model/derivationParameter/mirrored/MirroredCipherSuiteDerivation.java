/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter.mirrored;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.LegacyDerivationScope;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.LegacyConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/** */
public class MirroredCipherSuiteDerivation extends MirroredDerivationParameter<CipherSuite> {

    public MirroredCipherSuiteDerivation() {
        super(TlsParameterType.MIRRORED_CIPHERSUITE, TlsParameterType.CIPHER_SUITE, CipherSuite.class);
    }

    public MirroredCipherSuiteDerivation(CipherSuite selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, LegacyDerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        DerivationFactory.getInstance(getMirroredType())
                .getParameterValues(context, scope)
                .forEach(
                        derivation ->
                                parameterValues.add(
                                        new MirroredCipherSuiteDerivation(
                                                ((CipherSuiteDerivation) (derivation))
                                                        .getSelectedValue())));
        return parameterValues;
    }

    @Override
    public List<LegacyConditionalConstraint> getDefaultConditionalConstraints(LegacyDerivationScope scope) {
        List<LegacyConditionalConstraint> condConstraints = new LinkedList<>();
        Set<TlsParameterType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(TlsParameterType.CIPHER_SUITE);
        condConstraints.add(new LegacyConditionalConstraint(
                        requiredDerivations,
                        ConstraintBuilder.constrain(getType().name(), TlsParameterType.CIPHER_SUITE.name())
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
}
