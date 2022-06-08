/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.config.delegates;

import java.util.Arrays;

public enum ConfigDelegates {
    SERVER("server"),
    CLIENT("client"),
    EXTRACT_TESTS("extractTests");

    private final String commandName;

    private ConfigDelegates(String commandName) {
        this.commandName = commandName;
    }

    public String getCommand() {
        return commandName;
    }

    public static ConfigDelegates delegateForCommand(String command) {
        return Arrays.stream(ConfigDelegates.values())
                .filter(i -> i.getCommand().equals(command))
                .findFirst()
                .orElse(null);
    }
}
