package de.rwth.swc.coffee4j.model.constraints;

import java.util.List;

/**
 * Defines a function to constrain a given number of values. For the same {@link ConstraintFunction} the number of
 * values is always the same if this class is used with {@link Constraint}. Easier implementable variants for
 * Lambda expressions are available at {@link BooleanFunction1} through{@link BooleanFunction6}.
 */
@FunctionalInterface
public interface ConstraintFunction {
    
    /**
     * Checks whether the given values are a valid combination or one which should not appear.
     *
     * @param arguments the values
     * @return {@code true} iff the values form a valid combination
     */
    boolean check(List<?> arguments);
    
}
