package de.rwth.swc.coffee4j.model.constraints;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.List;

/**
 * A helper function used to define constraints which involves three parameters.
 *
 * @param <A> type of the first parameter
 * @param <B> type of the second parameter
 * @param <C> type of the third parameter
 */
@FunctionalInterface
public interface BooleanFunction3<A, B, C> extends ConstraintFunction {
    
    @SuppressWarnings("unchecked")
    default boolean check(List<?> arguments) {
        Preconditions.notNull(arguments);
        Preconditions.check(arguments.size() == 3);
        
        final A a = (A) arguments.get(0);
        final B b = (B) arguments.get(1);
        final C c = (C) arguments.get(2);
        
        return apply(a, b, c);
    }
    
    /**
     * Checks whether the value combination give for the parameters is allowed.
     *
     * @param a the value for the first parameter
     * @param b the value for the second parameter
     * @param c the value for the third parameter
     * @return whether the value combination is allowed
     */
    boolean apply(A a, B b, C c);
    
}
