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
 */
public enum ConfigOptionDerivationType implements DerivationType {
    DisablePSK,
    TodoMoreOptions;

    public boolean isBitmaskDerivation() {
        return false;
    }
}

