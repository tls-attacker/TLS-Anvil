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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class NamedGroupDerivation extends DerivationParameter<NamedGroup> {

    public NamedGroupDerivation() {
        super(DerivationType.NAMED_GROUP, NamedGroup.class);
    }

    public NamedGroupDerivation(NamedGroup group) {
        this();
        setSelectedValue(group);
    }

    @Override
    public List<DerivationParameter> getParameterValues(
            TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        List<NamedGroup> groupList = context.getFeatureExtractionResult().getSupportedTls13Groups();
        if (!scope.isTls13Test()
                || scope.getKeyExchangeRequirements().supports(KeyExchangeType.ECDH)) {
            groupList = context.getFeatureExtractionResult().getSupportedNamedGroups();
            parameterValues.add(new NamedGroupDerivation(null));
        } else if (scope.isTls13Test()
                && context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            groupList = context.getFeatureExtractionResult().getSupportedTls13Groups();
        }
        groupList =
                groupList.stream()
                        .filter(group -> NamedGroup.getImplemented().contains(group))
                        .collect(Collectors.toList());
        groupList.forEach(group -> parameterValues.add(new NamedGroupDerivation(group)));

        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        if (getSelectedValue() != null) {
            if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
                config.setDefaultClientNamedGroups(getSelectedValue());
                config.setDefaultClientKeyShareNamedGroups(getSelectedValue());
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
        if (getSelectedValue() != null
                && context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            Set<NamedGroup> groups = new HashSet<NamedGroup>();
            NamedGroup selectedGroup = getSelectedValue();
            ServerFeatureExtractionResult extractionResult =
                    (ServerFeatureExtractionResult) context.getFeatureExtractionResult();
            NamedGroupWitness witness =
                    extractionResult.getNamedGroupWitnesses().get(selectedGroup);
            groups.add(selectedGroup);
            if (witness != null) {
                if (config.getDefaultSelectedCipherSuite().isEphemeral()) {
                    groups.add(witness.getEcdsaPkGroupEphemeral());
                    groups.add(witness.getEcdsaSigGroupEphemeral());
                } else {
                    groups.add(witness.getEcdsaSigGroupStatic());
                }
            }
            groups.remove(null);
            config.setDefaultClientNamedGroups(new LinkedList<>(groups));
        }
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        if (!scope.isTls13Test()) {
            if (ConstraintHelper.ecdhCipherSuiteModeled(scope)
                    && ConstraintHelper.nullModeled(scope, getType())) {
                condConstraints.add(getMustNotBeNullForECDHConstraint());
            }

            if (ConstraintHelper.nonEcdhCipherSuiteModeled(scope)) {
                condConstraints.add(getMustBeNullForNonECDHConstraint());
            }

            if (ConstraintHelper.staticEcdhCipherSuiteModeled(scope)) {
                condConstraints.add(getMustBeNullForStaticECDH());
            }
        }

        return condConstraints;
    }

    private ConditionalConstraint getMustNotBeNullForECDHConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name())
                        .by(
                                (NamedGroupDerivation namedGroupDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    NamedGroup selectedNamedGroup =
                                            namedGroupDerivation.getSelectedValue();
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    if (selectedNamedGroup == null
                                            && AlgorithmResolver.getKeyExchangeAlgorithm(
                                                            selectedCipherSuite)
                                                    .isKeyExchangeEcdh()) {
                                        return false;
                                    }
                                    return true;
                                }));
    }

    private ConditionalConstraint getMustBeNullForNonECDHConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name())
                        .by(
                                (NamedGroupDerivation namedGroupDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    NamedGroup selectedNamedGroup =
                                            namedGroupDerivation.getSelectedValue();
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    if (selectedNamedGroup != null
                                            && !AlgorithmResolver.getKeyExchangeAlgorithm(
                                                            selectedCipherSuite)
                                                    .isKeyExchangeEcdh()) {
                                        return false;
                                    }
                                    return true;
                                }));
    }

    private ConditionalConstraint getMustBeNullForStaticECDH() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name())
                        .by(
                                (NamedGroupDerivation namedGroupDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    NamedGroup selectedNamedGroup =
                                            namedGroupDerivation.getSelectedValue();
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    if (selectedNamedGroup != null
                                            && AlgorithmResolver.getKeyExchangeAlgorithm(
                                                            selectedCipherSuite)
                                                    .isKeyExchangeEcdh()
                                            && !selectedCipherSuite.isEphemeral()) {
                                        return false;
                                    }
                                    return true;
                                }));
    }
}
