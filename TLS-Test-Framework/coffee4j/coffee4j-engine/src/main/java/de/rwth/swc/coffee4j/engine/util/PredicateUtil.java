package de.rwth.swc.coffee4j.engine.util;

import java.util.function.Predicate;

/**
 * Utilities used in context of java {@link Predicate}.
 */
public final class PredicateUtil {
    
    private PredicateUtil() {
    }
    
    /**
     * Negates the given predicate. This can be used in streams when casting
     * the method reference to a predicate is not really legible.
     *
     * @param predicate the predicate to be negated
     * @param <T>       the type of the predicate
     * @return the negated predicate or {@code null} if the given predicate
     * was {@code null}
     */
    public static <T> Predicate<T> not(Predicate<T> predicate) {
        if (predicate == null) {
            return null;
        }
        
        return predicate.negate();
    }
}
