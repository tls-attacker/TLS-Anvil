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
                .filter(i -> command.equals(i.getCommand()))
                .findFirst()
                .orElse(null);
    }
}
