/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter;

import com.fasterxml.jackson.annotation.JsonValue;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionParameterType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class ConfigurationOptionCompoundDerivation
        extends DerivationParameter<Config, List<ConfigurationOptionDerivationParameter>> {

    private final List<List<ConfigurationOptionDerivationParameter>> configOptionsSetupsList;

    @SuppressWarnings("unchecked")
    public ConfigurationOptionCompoundDerivation(
            List<List<ConfigurationOptionDerivationParameter>> setupsList) {
        super(
                (Class<List<ConfigurationOptionDerivationParameter>>) (Object) List.class,
                Config.class,
                new ParameterIdentifier(
                        ConfigOptionParameterType.CONFIG_OPTION_COMPOUND_PARAMETER));
        configOptionsSetupsList = setupsList;
    }

    public ConfigurationOptionCompoundDerivation() {
        super(
                (Class<List<ConfigurationOptionDerivationParameter>>) (Object) List.class,
                Config.class,
                new ParameterIdentifier(
                        ConfigOptionParameterType.CONFIG_OPTION_COMPOUND_PARAMETER));
        configOptionsSetupsList = new LinkedList<>();
    }

    private ConfigurationOptionCompoundDerivation(
            List<List<ConfigurationOptionDerivationParameter>> setupsList,
            List<ConfigurationOptionDerivationParameter> selectedValue) {
        this(setupsList);
        setSelectedValue(selectedValue);
    }

    public <T extends ConfigurationOptionDerivationParameter> T getDerivation(Class<T> clazz) {
        for (ConfigurationOptionDerivationParameter coParam : getSelectedValue()) {
            if (clazz.equals(coParam.getClass())) {
                @SuppressWarnings("unchecked") // if statement already checks class
                T castedCOParam = (T) coParam;
                return (T) castedCOParam;
            }
        }
        return null;
    }

    /** Signal end of current test to allow the docker container to go to sleep */
    public void containerUsageEnded() {
        Set<ConfigurationOptionDerivationParameter> configOptionDerivations =
                new HashSet<>(getSelectedValue());
        ConfigurationOptionsDerivationManager.getInstance()
                .getConfigurationOptionsBuildManager()
                .onTestFinished(configOptionDerivations);
    }

    public FeatureExtractionResult getAssociatedFeatureExtractionResult() {
        return ConfigurationOptionsDerivationManager.getInstance()
                .getCompoundFeatureExtractionResult()
                .get(getSelectedValue());
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        condConstraints.add(getWeakCipherSuitesMustBeEnabledToBeUsedConstraint());
        return condConstraints;
    }

    private boolean isWeakCiphersuite(CipherSuite cipherSuite) {
        boolean isWeak = cipherSuite.isWeak();
        isWeak = isWeak || cipherSuite.name().contains("RC2");
        isWeak = isWeak || cipherSuite.name().contains("RC4");
        isWeak = isWeak || cipherSuite.name().contains("MD5");
        isWeak = isWeak || cipherSuite.name().contains("DES"); // DES or 3DES

        return isWeak;
    }

    /**
     * When using the EnableWeakSslCiphersDerivation CO the CipherSuiteDerivation gets more cipher
     * suites in its list. This list is created BEFORE the test vector creation, so we cannot demand
     * from the Derivation that it only uses the weak cipher suites for tests with the
     * EnableWeakSslCiphersDerivation CO set. The only sensible workaround seems to be to add a
     * constraint to prevent combinations without the CO set and weak cipher suites.
     *
     * <p>Note that this method does not violate combinatorial testing (at least for one such
     * constraint).
     *
     * @return the constraint.
     */
    private ConditionalConstraint getWeakCipherSuitesMustBeEnabledToBeUsedConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));
        requiredDerivations.add(
                new ParameterIdentifier(
                        ConfigOptionParameterType.CONFIG_OPTION_COMPOUND_PARAMETER));
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getParameterIdentifier().name(),
                                TlsParameterType.CIPHER_SUITE.name())
                        .by(
                                (ConfigurationOptionCompoundDerivation coCompoundDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    EnableWeakSslCiphersDerivation enableWeakSslCiphersDerivation =
                                            coCompoundDerivation.getDerivation(
                                                    EnableWeakSslCiphersDerivation.class);
                                    if (enableWeakSslCiphersDerivation == null) {
                                        // The EnableWeakSslCiphersDerivation is not used, so the
                                        // cipher suite list has no weak cipher suites
                                        return true;
                                    }
                                    if (enableWeakSslCiphersDerivation
                                            .getSelectedValue()
                                            .isOptionSet()) {
                                        // Weak cipher suites are supported
                                        return true;
                                    }
                                    // Selected cipher suite must not be weak
                                    CipherSuite selectedCipherSuite =
                                            cipherSuiteDerivation.getSelectedValue();

                                    return !isWeakCiphersuite(selectedCipherSuite);
                                }));
    }

    @Override
    public void applyToConfig(Config config, DerivationScope derivationScope) {
        // set connection for container in config and ensure container is running
        Set<ConfigurationOptionDerivationParameter> configOptionDerivations =
                new HashSet<>(getSelectedValue());
        ConfigurationOptionsDerivationManager.getInstance()
                .getConfigurationOptionsBuildManager()
                .preparePeerConnection(config, TestContext.getInstance(), configOptionDerivations);
    }

    @Override
    public List<DerivationParameter<Config, List<ConfigurationOptionDerivationParameter>>>
            getParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter<Config, List<ConfigurationOptionDerivationParameter>>>
                parameterValues = new LinkedList<>();

        Set<ParameterType> scopeLimitations =
                derivationScope.getIpmLimitations().stream()
                        .map(ParameterIdentifier::getParameterType)
                        .collect(Collectors.toSet());
        for (List<ConfigurationOptionDerivationParameter> setup :
                ConfigurationOptionsDerivationManager.getInstance().getCompoundSetupList()) {
            List<ConfigurationOptionDerivationParameter> constrainedSetupList =
                    new LinkedList<>(setup);
            // Scope Limitations (Set respective parameters to their default value)
            for (int i = 0; i < constrainedSetupList.size(); i++) {
                ParameterType type =
                        constrainedSetupList.get(i).getParameterIdentifier().getParameterType();
                if (scopeLimitations.contains(type)) {
                    constrainedSetupList.set(
                            i, constrainedSetupList.get(i).getDefaultValueParameter());
                }
            }
            parameterValues.add(
                    new ConfigurationOptionCompoundDerivation(
                            this.configOptionsSetupsList, constrainedSetupList));
        }
        return parameterValues;
    }

    @Override
    protected DerivationParameter<Config, List<ConfigurationOptionDerivationParameter>>
            generateValue(List<ConfigurationOptionDerivationParameter> selectedValue) {
        throw new UnsupportedOperationException("CompoundDerivation also requires a setup list");
    }

    @JsonValue
    public String jsonValue() {
        StringBuilder stringBuilder = new StringBuilder();
        return getSelectedValue().stream()
                .map(
                        parameter -> {
                            return parameter.getParameterIdentifier().getParameterType()
                                    + ":"
                                    + parameter.getSelectedValue().toString();
                        })
                .collect(Collectors.joining(","));
    }
}
