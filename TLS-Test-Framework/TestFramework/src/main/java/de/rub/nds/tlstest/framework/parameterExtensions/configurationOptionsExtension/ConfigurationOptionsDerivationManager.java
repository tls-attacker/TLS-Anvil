/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import de.rub.nds.tlstest.framework.model.*;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

/**
 * The DerivationCategoryManager responsible for the ConfigOptionsDerivationType. It also contains the configured
 * ConfigurationOptionsConfig and knows the required ConfigurationOptionsBuildManager.
 */
public class ConfigurationOptionsDerivationManager implements DerivationCategoryManager {
    private static ConfigurationOptionsDerivationManager instance = null;
    private static final Logger LOGGER = LogManager.getLogger();
    private ConfigurationOptionsConfig config;

    public static synchronized ConfigurationOptionsDerivationManager getInstance() {
        if (ConfigurationOptionsDerivationManager.instance == null) {
            ConfigurationOptionsDerivationManager.instance = new ConfigurationOptionsDerivationManager();
        }
        return ConfigurationOptionsDerivationManager.instance;
    }

    private ConfigurationOptionsDerivationManager(){
        config = null;
    }

    @Override
    public DerivationParameter getDerivationParameterInstance(DerivationType type) {
        if(!(type instanceof ConfigOptionDerivationType)){
            throw new IllegalArgumentException("This manager can only handle ConfigOptionDerivationType but type '"+type+"' was passed.");
        }
        ConfigOptionDerivationType basicType = (ConfigOptionDerivationType) type;
        switch(basicType) {
            case DisablePsk:
                return new DisablePskDerivation();
            case SeedingMethod:
                return new SeedingMethodDerivation();
            case EnableNistEcOptimizations:
                return new EnableNistEcOptimizationsDerivation();
            case DisableSse2:
                return new DisableSse2Derivation();
            case DisableBinaryEllipticCurves:
                return new DisableBinaryEllipticCurvesDerivation();
            case DisableMultiblock:
                return new DisableMultiblockDerivation();
            case EnableCompression:
                return new EnableCompressionDerivation();

            case DisableAfalgEngine:
                return new DisableAfalgEngineDerivation();
            case EnableEntropyGatheringDaemon:
                return new EnableEntropyGatheringDaemonDerivation();
            case DisableRdrand:
                return new DisableRdrandDerivation();
            case DisableCertificateTransparency:
                return new DisableCertificateTransparencyDerivation();
            case DisableNextProtocolNegotiationExtension:
                return new DisableNextProtocolNegotiationExtensionDerivation();
            case DisableOcspSupport:
                return new DisableOcspSupportDerivation();
            case EnableWeakSslCiphers:
                return new EnableWeakSslCiphersDerivation();
            case EnableMd2:
                return new EnableMd2Derivation();
            case EnableRc5:
                return new EnableRc5Derivation();
            case DisableAssemblerCode:
                return new DisableAssemblerCodeDerivation();

            case DisablePadlockEngine:
                return new DisablePadlockEngineDerivation();
            case DisablePosixIo:
                return new DisablePosixIoDerivation();
            case DisableExtensionForIpAddressesAndAsIdentifiers:
                return new DisableExtensionForIpAddressesAndAsIdentifiersDerivation();
            case DisableSrpCiphersuites:
                return new DisableSrpCiphersuitesDerivation();
            case EnableDevelopmentFlags:
                return new EnableDevelopmentFlagsDerivation();
            case EnableMemoryDebuggingSupport:
                return new EnableMemoryDebuggingSupportDerivation();
            case DisableErrorStrings:
                return new DisableErrorStringsDerivation();

            default:
                LOGGER.error("Derivation Type {} not implemented", type);
                throw new UnsupportedOperationException("Derivation Type not implemented");
        }
    }

    @Override
    public List<DerivationType> getDerivationsOfModel(DerivationScope derivationScope, ModelType baseModel) {
        if(config == null){
            throw new IllegalStateException("No ConfigurationOptionsConfig was set so far. Register it before calling this method.");
        }
        return new LinkedList<>(config.getEnabledConfigOptionDerivations());
    }

    @Override
    public List<DerivationType> getAllDerivations() {
        return new LinkedList<>(config.getEnabledConfigOptionDerivations());
    }

    public List<DerivationType> getDerivationsOfModel(ModelType baseModel) {
        return getDerivationsOfModel(null, baseModel);
    }

    public void setConfigOptionsConfig(ConfigurationOptionsConfig optionsConfig){
        config = optionsConfig;
    }

    public ConfigurationOptionsConfig getConfigurationOptionsConfig(){
        return config;
    }

    public ConfigurationOptionsBuildManager getConfigurationOptionsBuildManager(){
        if(config == null){
            throw new IllegalStateException("No ConfigurationOptionsConfig was set so far. Register it before calling this method.");
        }
        return config.getBuildManager();
    }
}



























//