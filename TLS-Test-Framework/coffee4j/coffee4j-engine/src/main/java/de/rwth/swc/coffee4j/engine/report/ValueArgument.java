package de.rwth.swc.coffee4j.engine.report;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Objects;

/**
 * Used to encapsulate two ints as a value for a parameter. This is used to distinguish normal ints and values
 * for eventual argument conversion using an {@link ArgumentConverter}. Therefore, all values
 * should be reported in a {@link Report} using this class.
 */
public final class ValueArgument {
    
    private final int parameter;
    private final int value;
    
    /**
     * Creates a new argument for the value uniquely defined by both ints.
     *
     * @param parameter the parameter
     * @param value     a value of the given parameter
     */
    public ValueArgument(int parameter, int value) {
        Preconditions.check(parameter >= 0);
        Preconditions.check(value >= 0);
        
        this.parameter = parameter;
        this.value = value;
    }
    
    public static ValueArgument value(int parameter, int value) {
        return new ValueArgument(parameter, value);
    }
    
    public int getParameter() {
        return parameter;
    }
    
    public int getValue() {
        return value;
    }
    
    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        final ValueArgument other = (ValueArgument) object;
        return parameter == other.parameter && value == other.value;
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(parameter, value);
    }
    
    @Override
    public String toString() {
        return Integer.toString(parameter) + ':' + Integer.toString(value);
    }
    
}
