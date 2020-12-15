package de.rwth.swc.coffee4j.engine.report;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Objects;

/**
 * Used to encapsulate a int as a parameter. This is used to distinguish normal ints and parameters
 * for eventual argument conversion using an {@link ArgumentConverter}. Therefore, all parameters
 * should be reported in a {@link Report} using this class.
 */
public final class ParameterArgument {
    
    private final int parameter;
    
    /**
     * Creates a new argument with the given parameter.
     *
     * @param parameter the parameter for the argument
     */
    public ParameterArgument(int parameter) {
        Preconditions.check(parameter >= 0);
        
        this.parameter = parameter;
    }
    
    public static ParameterArgument parameter(int parameter) {
        return new ParameterArgument(parameter);
    }
    
    public int getParameter() {
        return parameter;
    }
    
    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        
        final ParameterArgument other = (ParameterArgument) object;
        return parameter == other.parameter;
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(parameter);
    }
    
    @Override
    public String toString() {
        return Integer.toString(parameter);
    }
    
}
