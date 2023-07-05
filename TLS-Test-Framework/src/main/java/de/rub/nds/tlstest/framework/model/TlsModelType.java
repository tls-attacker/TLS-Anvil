/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

import de.rub.nds.anvilcore.model.ModelType;

public enum TlsModelType implements ModelType {
    EMPTY,
    GENERIC,
    CERTIFICATE,
    LENGTHFIELD
}
