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

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.BasicDerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;

public class ConfigurationOptionCompoundDerivation extends DerivationParameter<List<ConfigurationOptionDerivationParameter>> {

    private final List<List<ConfigurationOptionDerivationParameter>> configOptionsSetupsList;

    @SuppressWarnings("unchecked")
    public ConfigurationOptionCompoundDerivation(List<List<ConfigurationOptionDerivationParameter>> setupsList){
        super(ConfigOptionDerivationType.ConfigurationOptionCompoundParameter, (Class<List<ConfigurationOptionDerivationParameter>>)(Object)List.class);
        configOptionsSetupsList = setupsList;
    }

    private ConfigurationOptionCompoundDerivation(List<List<ConfigurationOptionDerivationParameter>> setupsList,
                                                 List<ConfigurationOptionDerivationParameter> selectedValue){
        this(setupsList);
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();

        Set<DerivationType> scopeLimitations = new HashSet<>(scope.getScopeLimits());
        for(List<ConfigurationOptionDerivationParameter> setup : this.configOptionsSetupsList){
            List<ConfigurationOptionDerivationParameter> constrainedSetupList = new LinkedList<>(setup);
            // Scope Limitations (Set respective parameters to their default value)
            for(int i = 0; i < constrainedSetupList.size(); i++){
                DerivationType type = constrainedSetupList.get(i).getType();
                if(scopeLimitations.contains(type)){
                    ConfigurationOptionDerivationParameter defaultParam =
                            (ConfigurationOptionDerivationParameter) ConfigurationOptionsDerivationManager.getInstance()
                                    .getDerivationParameterInstance(type);

                    defaultParam.setSelectedValue(defaultParam.getDefaultValue());
                    constrainedSetupList.set(i, defaultParam);
                }
            }
            parameterValues.add(new ConfigurationOptionCompoundDerivation(this.configOptionsSetupsList, constrainedSetupList));
        }

        return parameterValues;
    }

    public <T extends ConfigurationOptionDerivationParameter> T getDerivation(Class<T> clazz) {
        for(ConfigurationOptionDerivationParameter coParam : getSelectedValue()) {
            if(clazz.equals(coParam.getClass())) {
                @SuppressWarnings("unchecked") // if statement already checks class
                T castedCOParam = (T)coParam;
                return (T)castedCOParam;
            }
        }
        return null;
    }

    @Override
    public void configureParameterDependencies(Config config, TestContext context, DerivationContainer container){
        Set<ConfigurationOptionDerivationParameter> configOptionDerivations = new HashSet<>(getSelectedValue());

        Callable<TestSiteReport> reportCallable = ConfigurationOptionsDerivationManager.getInstance()
                .getConfigurationOptionsBuildManager()
                .configureOptionSetAndReturnGetSiteReportCallable(config, context, configOptionDerivations);

        container.configureGetAssociatedSiteReportCallable(reportCallable);
    }

    @Override
    public void onContainerFinalized(DerivationContainer container) {
        super.onContainerFinalized(container);

        Set<ConfigurationOptionDerivationParameter> configOptionDerivations = new HashSet<>(getSelectedValue());
        ConfigurationOptionsDerivationManager.getInstance().getConfigurationOptionsBuildManager().onTestFinished(configOptionDerivations);
    }


    @Override
    public void applyToConfig(Config config, TestContext context) { }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        // The constraint for weak cipher suites must not be added if there is no weak cipher suite
        boolean testHasWeakCipherSuites = false;
        if(!scope.isTls13Test()){
            for(CipherSuite cipherSuite : TestContext.getInstance().getSiteReport().getCipherSuites()){
                if(this.isWeakCiphersuite(cipherSuite)){
                    testHasWeakCipherSuites = true;
                    break;
                }
            }
        }

        if(testHasWeakCipherSuites && ConfigurationOptionsDerivationManager.getInstance().getAllActivatedCOTypes().contains(ConfigOptionDerivationType.EnableWeakSslCiphers)){
            condConstraints.add(getWeakCipherSuitesMustBeEnabledToBeUsedConstraint());
        }

        return condConstraints;
    }

    private boolean isWeakCiphersuite(CipherSuite cipherSuite){
        boolean isWeak = cipherSuite.isWeak();
        isWeak = isWeak || cipherSuite.name().contains("RC2");
        isWeak = isWeak || cipherSuite.name().contains("RC4");
        isWeak = isWeak || cipherSuite.name().contains("MD5");
        isWeak = isWeak || cipherSuite.name().contains("DES"); // DES or 3DES
        
        return isWeak;
    }

    /**
     * When using the EnableWeakSslCiphersDerivation CO the CipherSuiteDerivation gets more cipher suites in its list.
     * This list is created BEFORE the test vector creation, so we cannot demand from the Derivation that it only
     * uses the weak cipher suites for tests with the EnableWeakSslCiphersDerivation CO set. The only sensible workaround
     * seems to be to add a constraint to prevent combinations without the CO set and weak cipher suites.
     *
     * Note that this method does not violate combinatorial testing (at least for one such constraint). 
     *
     * @return the constraint.
     */
    private ConditionalConstraint getWeakCipherSuitesMustBeEnabledToBeUsedConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(BasicDerivationType.CIPHERSUITE);
        requiredDerivations.add(ConfigOptionDerivationType.ConfigurationOptionCompoundParameter);
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(ConfigOptionDerivationType.ConfigurationOptionCompoundParameter.name(), BasicDerivationType.CIPHERSUITE.name()).withName("WeakCipherSuitesMustBeEnabledToBeUsed").by((ConfigurationOptionCompoundDerivation coCompoundDerivation, CipherSuiteDerivation cipherSuiteDerivation) -> {
            EnableWeakSslCiphersDerivation enableWeakSslCiphersDerivation = coCompoundDerivation.getDerivation(EnableWeakSslCiphersDerivation.class);
            if(enableWeakSslCiphersDerivation == null){
                // The EnableWeakSslCiphersDerivation is not used, so the cipher suite list has no weak cipher suites
                return true;
            }
            if(enableWeakSslCiphersDerivation.getSelectedValue().isOptionSet()){
                // Weak cipher suites are supported
                return true;
            }
            // Selected cipher suite must not be weak
            CipherSuite selectedCipherSuite = cipherSuiteDerivation.getSelectedValue();

            return !isWeakCiphersuite(selectedCipherSuite);
        }));
    }

}
