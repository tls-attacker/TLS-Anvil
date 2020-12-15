package de.rwth.swc.coffee4j.engine.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A wrapper class for integer arrays so that they can be used inside collections. The default
 * {@link Object#equals(Object)} and {@link Object#hashCode()} implementation depend only on the storage location
 * of an array and thus comparing to arrays via equals does not make sense and the hash code does not help either.
 * This class just wraps the array and uses {@link Arrays#equals(int[], int[])} and {@link Arrays#hashCode(int[])}.
 */
public final class IntArrayWrapper {
    
    private final int[] array;
    
    /**
     * Creates a new wrapper with the array. The array can be modified from the outside as not copy is used for
     * performance reasons.
     *
     * @param array the array to wrap
     */
    public IntArrayWrapper(int[] array) {
        this.array = array;
    }
    
    public int[] getArray() {
        return array;
    }
    
    /**
     * Convenience method for wrapping a int[] into a {@link IntArrayWrapper}.
     *
     * @param array the array to wrap
     * @return the wrapped array
     */
    public static IntArrayWrapper wrap(int[] array) {
        return new IntArrayWrapper(array);
    }
    
    /**
     * Convenience method for wrapping all int[] in a collection into a list.
     *
     * @param arrays the arrays to wrap
     * @return a list containing the wrapped arrays
     */
    public static List<IntArrayWrapper> wrapToList(Collection<int[]> arrays) {
        final List<IntArrayWrapper> wrappers = new ArrayList<>(arrays.size());
        wrapAll(wrappers, arrays);
        
        return wrappers;
    }
    
    private static void wrapAll(Collection<IntArrayWrapper> wrapped, Collection<int[]> arrays) {
        for (int[] array : arrays) {
            wrapped.add(wrap(array));
        }
    }
    
    /**
     * Convenience method for wrapping all int[] in a collection into a set.
     * As the wrappers contain sensible hashcode and equals functions, no duplicates are present in the set.
     *
     * @param arrays the arrays to wrap
     * @return a set containing the wrapped arrays
     */
    public static Set<IntArrayWrapper> wrapToSet(Collection<int[]> arrays) {
        final Set<IntArrayWrapper> wrappers = new HashSet<>(arrays.size());
        wrapAll(wrappers, arrays);
        
        return wrappers;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        
        final IntArrayWrapper that = (IntArrayWrapper) o;
        return Arrays.equals(array, that.array);
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(array);
    }
    
    @Override
    public String toString() {
        return Arrays.toString(array);
    }
    
}
