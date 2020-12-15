package de.rwth.swc.coffee4j.model.constraints;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.List;

/**
 * A helper function used to define constraints which involves five parameters.
 *
 * @param <A> type of the first parameter
 * @param <B> type of the second parameter
 * @param <C> type of the third parameter
 * @param <D> type of the fourth parameter
 * @param <E> type of the fifth parameter
 */
@FunctionalInterface
public interface BooleanFunction5<A, B, C, D, E> extends ConstraintFunction {
    
    @SuppressWarnings("unchecked")
    default boolean check(List<?> arguments) {
        Preconditions.notNull(arguments);
        Preconditions.check(arguments.size() == 5);
        
        final A a = (A) arguments.get(0);
        final B b = (B) arguments.get(1);
        final C c = (C) arguments.get(2);
        final D d = (D) arguments.get(3);
        final E e = (E) arguments.get(4);
        
        return apply(a, b, c, d, e);
    }
    
    /**
     * Checks whether the value combination give for the parameters is allowed.
     *
     * @param a the value for the first parameter
     * @param b the value for the second parameter
     * @param c the value for the third parameter
     * @param d the value for the fourth parameters
     * @param e the value for the fifth parameters
     * @return whether the value combination is allowed
     */
    boolean apply(A a, B b, C c, D d, E e);
    
}
