/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigOptionValueTranslation;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * A ConfigurationOptionsBuildManager knows how to build a specific TLS library in a specific
 * version range. It is used to provide library builds that use the specified configuration options
 * set. Also it is responsible to offer a TestSiteReport of the
 */
public abstract class ConfigurationOptionsBuildManager {

    /**
     * This function provides access to a TLS library that was built using the specified
     * configuration options set. The Config is manipulated so that the connection is delegated to
     * the required library. The implementation also provides a callable to get the TestSiteReport
     * as a return value that contains information about the library build that is chosen/built. A
     * Callable is used for lazy evaluation (so if a site report is not used, it is not created).
     *
     * @param config - the specified Config
     * @param context - the test context
     * @param optionSet - the set of configurationOptionDerivationParameters that contain selected
     *     values.
     * @return the TestSiteReport of the provided library build.
     */
    public abstract Callable<FeatureExtractionResult>
            configureOptionSetAndReturnGetSiteReportCallable(
                    Config config,
                    TestContext context,
                    Set<ConfigurationOptionDerivationParameter> optionSet);

    /**
     * Get the SiteReport for the tls library built that has the most possible available features
     * using the enabled configuration options.
     *
     * @return the TestSiteReport of the maximal build
     */
    public abstract FeatureExtractionResult getMaximalFeatureExtractionResult();

    /**
     * Method that should be called on the end of each test. Can be used to let the manager know
     * that a certain library built is not used anymore.
     *
     * @param optionSet - The option set of the test that is finished
     */
    public abstract void onTestFinished(Set<ConfigurationOptionDerivationParameter> optionSet);

    /** Method is called before the ConfigurationOptionsExtension is unloaded. */
    public void onShutdown() {}

    /** Method to initialize the respective build manager (e.g. initialize docker) */
    public void init() {}

    /**
     * Translates a given configuration option to a tls library specific string.
     *
     * @param optionParameter - the configuration option to translate (including its set value)
     * @param optionsToTranslationMap - the translation map of the configuration options config
     * @return the translated string
     */
    protected abstract String translateOptionValue(
            ConfigurationOptionDerivationParameter optionParameter,
            Map<ConfigOptionDerivationType, ConfigOptionValueTranslation> optionsToTranslationMap);
}
