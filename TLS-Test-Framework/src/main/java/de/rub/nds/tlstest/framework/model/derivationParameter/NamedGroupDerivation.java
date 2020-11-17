/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.probe.namedcurve.NamedCurveWitness;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import de.rwth.swc.coffee4j.model.constraints.ConstraintStatus;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 *
 * @author marcel
 */
public class NamedGroupDerivation extends DerivationParameter<NamedGroup> {

    public NamedGroupDerivation() {
        super(DerivationType.NAMED_GROUP, NamedGroup.class);
    }

    public NamedGroupDerivation(NamedGroup group) {
        this();
        setSelectedValue(group);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        context.getSiteReport().getSupportedNamedGroups().forEach(group -> parameterValues.add(new NamedGroupDerivation(group)));
        parameterValues.add(new NamedGroupDerivation(null));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        if (getSelectedValue() != null) {
            if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
                config.setDefaultClientNamedGroups(getSelectedValue());
            } else {
                config.setDefaultServerNamedGroups(getSelectedValue());
            }
            config.setDefaultSelectedNamedGroup(getSelectedValue());
        } else {
            config.setAddEllipticCurveExtension(false);
        }

    }

    @Override
    public void postProcessConfig(Config config, TestContext context) {
        if (getSelectedValue() != null && context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            Set<NamedGroup> groups = new HashSet<NamedGroup>();
            NamedGroup selectedGroup = getSelectedValue();
            NamedCurveWitness witness = context.getSiteReport().getSupportedNamedGroupsWitnesses().get(selectedGroup);
            groups.add(selectedGroup);
            if (config.getDefaultSelectedCipherSuite().isEphemeral()) {
                groups.add(witness.getEcdsaPkGroupEphemeral());
                groups.add(witness.getEcdsaSigGroupEphemeral());
            } else {
                groups.add(witness.getEcdsaSigGroupStatic());
            }

            groups.remove(null);
            config.setDefaultClientNamedGroups(new LinkedList<>(groups));
        }
    }

    @Override
    public List<ConditionalConstraint> getConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        if (ConstraintHelper.ecdhCipherSuiteModeled(scope)) {
            //TODO: do we want to handle it like this? i.e null = exclude extension
            Set<DerivationType> requiredDerivations = new HashSet<>();
            requiredDerivations.add(DerivationType.CIPHERSUITE);

            condConstraints.add(new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(DerivationType.NAMED_GROUP.name(), DerivationType.CIPHERSUITE.name()).by((DerivationParameter group, DerivationParameter cipherSuite) -> {
                NamedGroupDerivation groupDev = (NamedGroupDerivation) group;
                CipherSuiteDerivation cipherDev = (CipherSuiteDerivation) cipherSuite;
                if (groupDev.getSelectedValue() == null && AlgorithmResolver.getKeyExchangeAlgorithm(cipherDev.getSelectedValue()).isKeyExchangeEcdh()) {
                    return false;
                }
                return true;
            })));
        }
        return condConstraints;
    }

}
