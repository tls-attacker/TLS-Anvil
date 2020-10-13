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

import java.util.ArrayList;
import java.util.List;

public enum TestStatus {
    NOT_SPECIFIED(1, 0),
    SUCCEEDED(1 << 1, 100),
    PARTIALLY_SUCCEEDED(1 << 2, 80),
    PARTIALLY_FAILED(1 << 3, 20),
    FAILED(1 << 4, 0),
    DISABLED(1 << 5, 0);

    private final int value;
    private final int scorePercentage;

    TestStatus(int value, int scorePercentage) {
        this.value = value;
        this.scorePercentage = scorePercentage;
    }

    public int getValue() {
        return value;
    }

    public static List<TestStatus> parse(int val) {
        List<TestStatus> statusList = new ArrayList<TestStatus>();
        if (val == 0) {
            statusList.add(NOT_SPECIFIED);
            return statusList;
        }

        for (TestStatus ap : values()) {
            if ((val & ap.getValue()) > 0)
                statusList.add(ap);
        }
        return statusList;
    }

    public static TestStatus statusForBitmask(int val) {
        if (val == 0) {
            return NOT_SPECIFIED;
        }

        List<TestStatus> status = TestStatus.parse(val);
        if (status.size() == 1) {
            return status.get(0);
        }

        if (status.contains(DISABLED)) {
            throw new UnsupportedOperationException("TestStatus Bitmask contains DISABLED");
        }

        if (status.contains(NOT_SPECIFIED)) {
            throw new UnsupportedOperationException("TestStatus Bitmask contains NOT_SPECIFIED");
        }

        if (status.contains(FAILED) || status.contains(PARTIALLY_FAILED)) {
            if (status.contains(PARTIALLY_SUCCEEDED) || status.contains(SUCCEEDED)) {
                return PARTIALLY_FAILED;
            }
        }

        return status.get(status.size() - 1);
    }

    public int getScorePercentage() {
        return scorePercentage;
    }
}
