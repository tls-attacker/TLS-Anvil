/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.constants;

public enum TestStatus {
    NOT_SPECIFIED,
    SUCCEEDED,
    PARTIALLY_FAILED,
    PARTIALLY_SUCCEEDED,
    FAILED,
    DISABLED,
}
