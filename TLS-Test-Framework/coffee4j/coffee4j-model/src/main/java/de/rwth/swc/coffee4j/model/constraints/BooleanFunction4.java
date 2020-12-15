package de.rwth.swc.coffee4j.model.constraints;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.List;

/**
 * A helper function used to define constraints which involves four parameters.
 *
 * @param <A> type of the first parameter
 * @param <B> type of the second parameter
 * @param <C> type of the third parameter
 * @param <D> type of the fourth parameter
 */
@FunctionalInterface
public interface BooleanFunction4<A, B, C, D> extends ConstraintFunction {
    
    @SuppressWarnings("unchecked")
    default boolean check(List<?> arguments) {
        Preconditions.notNull(arguments);
        Preconditions.check(arguments.size() == 4);
        
        final A a = (A) arguments.get(0);
        final B b = (B) arguments.get(1);
        final C c = (C) arguments.get(2);
        final D d = (D) arguments.get(3);
        
        return apply(a, b, c, d);
    }
    
    /**
     * Checks whether the value combination give for the parameters is allowed.
     *
     * @param a the value for the first parameter
     * @param b the value for the second parameter
     * @param c the value for the third parameter
     * @param d the value for the fourth parameters
     * @return whether the value combination is allowed
     */
    boolean apply(A a, B b, C c, D d);
    
}
