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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class IncludeEncryptThenMacExtensionDerivation extends TlsDerivationParameter<Boolean> {

    public IncludeEncryptThenMacExtensionDerivation() {
        super(TlsParameterType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION, Boolean.class);
    }

    public IncludeEncryptThenMacExtensionDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public void applyToConfig(Config config, DerivationScope derivationScope) {
        config.setAddEncryptThenMacExtension(getSelectedValue());
    }

    @Override
    protected TlsDerivationParameter<Boolean> generateValue(Boolean selectedValue) {
        return new IncludeEncryptThenMacExtensionDerivation(selectedValue);
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        condConstraints.add(getNoEncryptThenMacOnAEADCiphersConstraint());
        return condConstraints;
    }

    private ConditionalConstraint getNoEncryptThenMacOnAEADCiphersConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getParameterIdentifier().name(),
                                TlsParameterType.CIPHER_SUITE.name())
                        .by(
                                (IncludeEncryptThenMacExtensionDerivation macDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    Boolean includeExtension = macDerivation.getSelectedValue();
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    return !includeExtension || !selectedCipherSuite.isAEAD();
                                }));
    }

    @Override
    public List<DerivationParameter<Config, Boolean>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<Config, Boolean>> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeEncryptThenMacExtensionDerivation(true));
        parameterValues.add(new IncludeEncryptThenMacExtensionDerivation(false));
        return parameterValues;
    }
}
