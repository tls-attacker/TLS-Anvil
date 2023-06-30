/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.constants;

public enum SeverityLevel {
    NOT_CLASSIFIED(0),
    INFORMATIONAL(20),
    LOW(40),
    MEDIUM(60),
    HIGH(80),
    CRITICAL(100);

    private int maxScore = 0;

    SeverityLevel(int val) {
        maxScore = val;
    }

    public int getMaxScore() {
        return maxScore;
    }
}
