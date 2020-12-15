package de.rwth.swc.coffee4j.engine.util;

import java.util.Collection;
import java.util.function.Supplier;

/**
 * Preconditions which can be used to validate the argument passed to methods.
 */
public final class Preconditions {
    
    private Preconditions() {
    }
    
    /**
     * Checks if the given object is {@code null}. If this is the case,
     * a {@link NullPointerException} is thrown.
     *
     * @param object the object to be checked
     * @param <T>    the type of the object. This is needed to return the correct
     *               type again
     * @return the object which was passed if it is not {@code null}
     * @throws NullPointerException if the passed object is {@code null}
     */
    public static <T> T notNull(T object) {
        return notNull(object, "Object must not be null");
    }
    
    /**
     * Checks if the given object if {@code null}. If this is the case,
     * a {@link NullPointerException} with the given message is thrown.
     *
     * @param object  the object to be checked
     * @param message the message for the exception if the object is
     *                {@code null}
     * @param <T>     the type of the object. This is needed to returned the correct
     *                type again
     * @return the object which was passed if it is not {@code null}
     * @throws NullPointerException if the passed object is {@code null}
     */
    public static <T> T notNull(T object, String message) {
        if (object == null) {
            throw new NullPointerException(message);
        }
        
        return object;
    }
    
    /**
     * Checks if the given object is {@code null}. If this is the case,
     * a {@link NullPointerException} with the message provided by the
     * {@link Supplier} is thrown.
     *
     * @param object          the object to be checked
     * @param messageSupplier a supplier for the message of the exception
     *                        which will be thrown if object is {@code null}
     * @param <T>             the type of the object. This is needed to returned the correct
     *                        *            type again
     * @return the object which was passed if it is not {@code null}
     * @throws NullPointerException if the passed object is {@code null}
     */
    public static <T> T notNull(T object, Supplier<String> messageSupplier) {
        if (object == null) {
            throw new NullPointerException(messageSupplier.get());
        }
        
        return object;
    }
    
    /**
     * Checks if the given {@link Collection} contains any {@code null} element.
     * If this is the case, a {@link IllegalArgumentException} is thrown.
     *
     * @param collection to be examined for a {@code null} element.
     *                   Must not be {@code null}
     * @param <T>        the type of the collection
     * @return the same collection which was initally given to this method
     * @throws IllegalArgumentException if collection contains {@code null}
     * @throws NullPointerException     if the collection it was {@code null}
     *                                  itself. Note that some {@link Collection}
     *                                  implementations may throw a
     *                                  {@link NullPointerException} during the
     *                                  check if they do not permit the {@code null}
     *                                  type
     */
    public static <T> Collection<T> doesNotContainNull(Collection<T> collection) {
        return doesNotContainNull(collection, "The collection must not contain null");
    }
    
    /**
     * Checks if the given {@link Collection} contains any {@code null} element.
     * If this is the case, a {@link IllegalArgumentException} with the given
     * message is thrown.
     *
     * @param collection to be examined for a {@code null} element.
     *                   Must not be {@code null}
     * @param message    for the exception if it is thrown
     * @param <T>        the type of the collection
     * @return the same collection which was initally given to this method
     * @throws IllegalArgumentException if collection contains {@code null}
     * @throws NullPointerException     if the collection it was {@code null}
     *                                  itself. Note that some {@link Collection}
     *                                  implementations may throw a
     *                                  {@link NullPointerException} during the
     *                                  check if they do not permit the {@code null}
     *                                  type
     */
    public static <T> Collection<T> doesNotContainNull(Collection<T> collection, String message) {
        if (collection.contains(null)) {
            throw new IllegalArgumentException(message);
        }
        
        return collection;
    }
    
    /**
     * Checks if the given {@link Collection} contains any {@code null} element.
     * If this is the case, a {@link IllegalArgumentException} with the message
     * given by the supplier.
     *
     * @param collection      to be examined for a {@code null} element.
     *                        Must not be {@code null}
     * @param messageSupplier for the exception message if it is thrown
     * @param <T>             the type of the collection
     * @return the same collection which was initally given to this method
     * @throws IllegalArgumentException if collection contains {@code null}
     * @throws NullPointerException     if the collection it was {@code null}
     *                                  itself. Note that some {@link Collection}
     *                                  implementations may throw a
     *                                  {@link NullPointerException} during the
     *                                  check if they do not permit the {@code null}
     *                                  type
     */
    public static <T> Collection<T> doesNotContainNull(Collection<T> collection, Supplier<String> messageSupplier) {
        if (collection.contains(null)) {
            throw new IllegalArgumentException(messageSupplier.get());
        }
        
        return collection;
    }
    
    /**
     * Checks whether the given expression evaluates to {@code true}. If this is
     * not the case, an {@link IllegalArgumentException} is thrown.
     *
     * @param expression the expression to be evaluated
     * @throws IllegalArgumentException if the expression evaluates to
     *                                  {@code false}
     */
    public static void check(boolean expression) {
        check(expression, "The expression must not evaluate to false");
    }
    
    /**
     * Checks whether the given expression evaluates to {@code true}. If this is
     * not the case, an {@link IllegalArgumentException} with the given message
     * is thrown.
     *
     * @param expression the expression to be evaluated
     * @param message    the message for the exception
     * @throws IllegalArgumentException if the expression evaluates to
     *                                  {@code false}
     */
    public static void check(boolean expression, String message) {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }
    
    /**
     * Checks whether the given expression evaluates to {@code true}. If this is
     * not the case, an {@link IllegalArgumentException} with the message given
     * by the {@link Supplier} is thrown.
     *
     * @param expression      the expression to be evaluated
     * @param messageSupplier the supplier for the exception message
     * @throws IllegalArgumentException if the expression evaluates to
     *                                  {@code false}
     */
    public static void check(boolean expression, Supplier<String> messageSupplier) {
        if (!expression) {
            throw new IllegalArgumentException(messageSupplier.get());
        }
    }
}
