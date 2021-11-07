package de.rwth.swc.coffee4j.engine.report;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Arrays;

/**
 * Used to encapsulate a int[] as a combination. This is used to distinguish normal int[] and test inputs or combinations
 * for eventual argument conversion using an {@link ArgumentConverter}. Therefore, all combinations and test inputs
 * should be reported in a {@link Report} using this class.
 */
public final class CombinationArgument {
    
    private final int[] combination;
    
    /**
     * Creates a new argument for the given combination.
     *
     * @param combination the combination
     */
    public CombinationArgument(int[] combination) {
        Preconditions.notNull(combination);
        
        this.combination = Arrays.copyOf(combination, combination.length);
    }
    
    public static CombinationArgument combination(int[] combination) {
        return new CombinationArgument(combination);
    }
    
    public int[] getCombination() {
        return Arrays.copyOf(combination, combination.length);
    }
    
    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        
        final CombinationArgument other = (CombinationArgument) object;
        return Arrays.equals(combination, other.combination);
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(combination);
    }
    
    @Override
    public String toString() {
        return Arrays.toString(combination);
    }
    
}
