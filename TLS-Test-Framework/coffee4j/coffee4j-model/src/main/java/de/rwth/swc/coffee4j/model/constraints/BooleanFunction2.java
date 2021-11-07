package de.rwth.swc.coffee4j.model.constraints;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.List;

/**
 * A helper function used to define constraints which involves two parameters.
 *
 * @param <A> type of the first parameter
 * @param <B> type of the second parameter
 */
@FunctionalInterface
public interface BooleanFunction2<A, B> extends ConstraintFunction {
    
    @SuppressWarnings("unchecked")
    default boolean check(List<?> arguments) {
        Preconditions.notNull(arguments);
        Preconditions.check(arguments.size() == 2);
        
        final A a = (A) arguments.get(0);
        final B b = (B) arguments.get(1);
        
        return apply(a, b);
    }
    
    /**
     * Checks whether the value combination give for the parameters is allowed.
     *
     * @param a the value for the first parameter
     * @param b the value for the second parameter
     * @return whether the value combination is allowed
     */
    boolean apply(A a, B b);
    
}
