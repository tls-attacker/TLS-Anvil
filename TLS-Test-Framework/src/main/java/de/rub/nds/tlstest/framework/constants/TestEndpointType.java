package de.rub.nds.tlstest.framework.constants;

public enum TestEndpointType {
    CLIENT("client"),
    SERVER("server"),
    BOTH("both");

    private final String mode;

    TestEndpointType(final String mode) {
        this.mode = mode;
    }

    @Override
    public String toString() {
        return this.mode;
    }
}
