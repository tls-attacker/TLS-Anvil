/**
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsBuildManager;

/**
 * The OpenSSLBuildManager is a ConfigurationOptionsBuildManager to build modern OpenSSL versions.
 */
public class OpenSSLBuildManager implements ConfigurationOptionsBuildManager {
    private static OpenSSLBuildManager instance = null;

    public static synchronized OpenSSLBuildManager getInstance() {
        if (OpenSSLBuildManager.instance == null) {
            OpenSSLBuildManager.instance = new OpenSSLBuildManager();
        }
        return OpenSSLBuildManager.instance;
    }

    @Override
    public TestSiteReport configureOptionSetAndGetSiteReport(Config config, TestContext context/*, Set<ConfigurationOptionDerivationParameter> optionSet*/) {
        // TODO
        return null;
    }
}
