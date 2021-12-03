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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;

import java.util.Set;

/**
 * A ConfigurationOptionsBuildManager knows how to build a specific TLS library in a specific version range. It is
 * used to provide library builds that use the specified configuration options set. Also it is responsible to offer
 * a TestSiteReport of the
 */
public interface ConfigurationOptionsBuildManager {
    /**
     * This function provides access to a TLS library that was built using the specified configuration options set.
     * The Config is manipulated so that the connection is delegated to the required library. The implementation
     * also provides a TestSiteReport as a return value that contains information about library build that is chosen/built.
     *
     * @param config - the specified Config
     * @param context - the test context
     * @param optionSet - the set of configurationOptionDerivationParameters that contain selected values.
     * @returns the TestSiteReport of the provided library build.
     */
    TestSiteReport configureOptionSetAndGetSiteReport(Config config, TestContext context, Set<ConfigurationOptionDerivationParameter> optionSet);

    TestSiteReport createSiteReportFromOptionSet(Set<ConfigurationOptionDerivationParameter> optionSet);
}
