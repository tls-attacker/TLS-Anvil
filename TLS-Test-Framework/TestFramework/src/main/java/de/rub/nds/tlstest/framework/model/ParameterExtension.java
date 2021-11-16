/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

/**
 * Interface for parameter extensions. Parameter extensions may use the DerivationManager to register additional derivation types.
 * Note that any new parameter extension has to be known by the ParameterExtensionManager, to be used.
 */
public interface ParameterExtension {
    boolean load();
    boolean unload();
    String getIdentifier();
}
