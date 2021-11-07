package de.rwth.swc.coffee4j.engine.util;

import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import de.rwth.swc.coffee4j.engine.constraint.NoConstraintChecker;
import gnu.trove.list.TIntList;
import gnu.trove.list.array.TIntArrayList;
import it.unimi.dsi.fastutil.ints.IntSet;

import java.util.Arrays;

/**
 * Common utilities used for integer array which represent combinations or test inputs. All combinations are represented
 * by an array containing the value indexes for each parameter. This means the parameters are 0 through array length
 * minus one. For example, if the first parameter is set to its first value, and the second one to its third value,
 * the resulting array would look like this. [0, 2].
 * If a parameter does not have a value in a combination, this is represented via {@link CombinationUtil#NO_VALUE}.
 */
public final class CombinationUtil {
    
    /**
     * The value used to indicate that a parameter has not been assigned a value in a combination.
     */
    public static final int NO_VALUE = -1;
    
    private CombinationUtil() {
    }
    
    /**
     * Creates a new combinations which is empty. A combinations is empty if no parameter has a set value, so each entry
     * of the returned array is {@link CombinationUtil#NO_VALUE}.
     * For example, for the size 5, [-1, -1, -1, -1, -1] is returned.
     *
     * @param size the number of parameters for the combinations. Must be greater that or equal to zero
     * @return a combination with the given number of parameters all set to {@link CombinationUtil#NO_VALUE}
     */
    public static int[] emptyCombination(int size) {
        Preconditions.check(size >= 0);
        
        final int[] combination = new int[size];
        Arrays.fill(combination, NO_VALUE);
        
        return combination;
    }
    
    /**
     * Checks whether the first combinations contains the second one. The contains relation is defined as follows:
     * A combination contains another combination if it has the same values for all values which are set in the
     * other combination.
     * Here is a list of two example combinations and a value for stating whether the first one contains the second one:
     * [0] [-1] true
     * [-1] [0] false
     * [0] [0] true
     * [-1] [-1] true
     * Both combinations need to be of the same length.
     *
     * @param firstCombination  a combination. Must not be {@code null}
     * @param secondCombination a combination for which it is checked whether it is contained in the first one. Must not
     *                          be {@code null} and must be of the same size as the first combination
     * @return whether the second combination is contained in the first one as defined by the rules above
     */
    public static boolean contains(int[] firstCombination, int[] secondCombination) {
        checkNotNullAndSameLength(firstCombination, secondCombination);
        
        for (int i = 0; i < firstCombination.length; i++) {
            if (secondCombination[i] != NO_VALUE && firstCombination[i] != secondCombination[i]) {
                return false;
            }
        }
        
        return true;
    }
    
    private static void checkNotNullAndSameLength(int[] first, int[] second) {
        Preconditions.notNull(first);
        Preconditions.notNull(second);
        Preconditions.check(first.length == second.length);
    }
    
    /**
     * Checks whether the combinations to be added can be added to the given combinations. A combination can added if
     * it either has the exact same value for each index, or another value iff the original combination's value at that
     * position has not been set, or the other value is the empty value.
     * Examples:
     * [0] [0] true
     * [-1] [0] true
     * [0] [-1] true
     * [-1] [-1] true
     * [0] [1] false
     * [0, -1] [0, 1] true
     * Both combinations have to be of the same length. It is further checked whether the resulting combination would
     * satisfy the given constraints checker.
     *
     * @param combination       a combination. Must not be {@code null}
     * @param toBeAdded         another combination which should be added to the first one. Must not be {@code null} and must be
     *                          of the same size as the first combination
     * @param constraintChecker checks whether the result combination would be valid. Must not be {@code null}. If this
     *                          is not important, pass a
     *                          {@link NoConstraintChecker}
     * @return whether the combination to be added can be added according to the rules explained above
     */
    public static boolean canBeAdded(int[] combination, int[] toBeAdded, ConstraintChecker constraintChecker) {
        Preconditions.notNull(constraintChecker);
        checkNotNullAndSameLength(combination, toBeAdded);
        
        for (int i = 0; i < toBeAdded.length; i++) {
            if (toBeAdded[i] != NO_VALUE && !(combination[i] == NO_VALUE || combination[i] == toBeAdded[i])) {
                return false;
            }
        }
        
        final TIntList dual = new TIntArrayList();
        for (int i = 0; i < toBeAdded.length; i++) {
            if (toBeAdded[i] != NO_VALUE) {
                dual.add(i);
                dual.add(toBeAdded[i]);
            }
        }
        
        return constraintChecker.isExtensionValid(combination, dual.toArray());
    }
    
    /**
     * Adds the combination to be added to the first one. This means all values in the first combination are overwritten
     * except if the ones which would be overwriting are {@link CombinationUtil#NO_VALUE}.
     * {@link #canBeAdded(int[], int[], ConstraintChecker)} would return {@code true} for both combinations if the
     * result combinations only differs form the first given combinations in places where it was
     * {@link CombinationUtil#NO_VALUE}. Examples:
     * [0] [-1] becomes [0]
     * [-1] [0] becomes [0]
     * [0, -1, 2, -1] [-1, 2, 2, -1] becomes [0, 2, 2, -1]
     *
     * @param combination a combination. Must not be {@code null}
     * @param toBeAdded   another combination which is added to the first one using the rules explained above. Must not
     *                    be {@code null} and must be the same length as the first combination
     */
    public static void add(int[] combination, int[] toBeAdded) {
        checkNotNullAndSameLength(combination, toBeAdded);
        
        for (int i = 0; i < toBeAdded.length; i++) {
            if (toBeAdded[i] != NO_VALUE) {
                combination[i] = toBeAdded[i];
            }
        }
    }
    
    /**
     * Checks whether a combinations contains all parameter, that is whether the field for all given parameters is
     * not set to {@link CombinationUtil#NO_VALUE}.
     *
     * @param combination      the combination. Must not be {@code null}
     * @param parameterIndices the parameter to check. Must not be {@code null} but can be empty
     * @return whether the given combination contains all parameters
     */
    public static boolean containsAllParameters(int[] combination, IntSet parameterIndices) {
        Preconditions.notNull(combination);
        Preconditions.notNull(parameterIndices);
        
        for (int parameterIndex : parameterIndices) {
            if (parameterIndex < 0 || parameterIndex >= combination.length || combination[parameterIndex] == NO_VALUE) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Checks whether all the combination contains all parameters until the given index, that is whether all fields
     * in the combination array until the index are not set to {@link CombinationUtil#NO_VALUE}.
     *
     * @param combination    a combination
     * @param untilParameter the parameter index until which to check (inclusively
     * @return whether the combinations does not have {@link CombinationUtil#NO_VALUE} on any given parameter index
     */
    public static boolean containsAllParameters(int[] combination, int untilParameter) {
        Preconditions.notNull(combination);
        
        if (untilParameter >= combination.length) {
            return false;
        }
        
        for (int parameter = 0; parameter <= untilParameter; parameter++) {
            if (combination[parameter] == NO_VALUE) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Checks whether the two combinations have exactly the same value for each of the given parameters.
     *
     * @param first      a combination. Must not be {@code null}
     * @param second     another combination. Must not be {@code null} and must be the same length as the first combination
     * @param parameters the parameters to check (indices)
     * @return whether both combinations have the given parameters set to the same value
     */
    public static boolean sameForAllGivenParameters(int[] first, int[] second, IntSet parameters) {
        checkNotNullAndSameLength(first, second);
        Preconditions.notNull(parameters);
        
        for (int parameter : parameters) {
            if (parameter >= 0 && parameter < first.length && (first[parameter] != second[parameter])) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Calculates the number of parameters in the combinations not set to {@link CombinationUtil#NO_VALUE}.
     *
     * @param combination a combination. Most not be {@code null}
     * @return the number of parameters in the combination not set
     */
    public static int numberOfSetParameters(int[] combination) {
        Preconditions.notNull(combination);
        
        int numberOfSetParameters = 0;
        for (int value : combination) {
            if (value != NO_VALUE) {
                numberOfSetParameters++;
            }
        }
        
        return numberOfSetParameters;
    }
}
