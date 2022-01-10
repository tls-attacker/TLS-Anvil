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

import de.rub.nds.tlstest.framework.model.DerivationType;

/**
 * All these types represent configuration options. Configuration options are library options that are configured at compile time
 * and are therefore NOT configured and negotiated during the TLS handshake. Note that not all of these options are supported by
 * every TLS-library.
 *
 * To implement new options (e.g. the option ExampleOption) the following steps need to be applied:
 * 1) Add ExampleOption to the ConfigOptionDerivationType enum below
 * 2) Add a new class 'ExampleOptionDerivation' in the package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.
 *    Implement the required functions like the other classes.
 * 3) Add the new class to the factory method 'ConfigurationOptionsDerivationManager.getDerivationParameterInstance(...)'
 * 4) To use the new option in your test, make sure to add it to your config options config file (together with the respective translation)
 * 5) If required: Add constraints regarding your new option to the required tests in your testsuite.
 */
public enum ConfigOptionDerivationType implements DerivationType {
    DisablePSK,
    SeedingMethod;
    //Todo: MoreOptions;

    public boolean isBitmaskDerivation() {
        return false;
    }
}

