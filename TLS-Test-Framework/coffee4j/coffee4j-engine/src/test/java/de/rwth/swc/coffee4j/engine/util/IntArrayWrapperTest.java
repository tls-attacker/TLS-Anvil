package de.rwth.swc.coffee4j.engine.util;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IntArrayWrapperTest {
    
    @Test
    void arrayWrapping() {
        final int[] nullArray = null;
        final IntArrayWrapper nullWrapper = new IntArrayWrapper(nullArray);
        assertNull(nullWrapper.getArray());
        
        final int[] array = new int[]{1, 2, 4, 3, 5, 3};
        final IntArrayWrapper wrapper = new IntArrayWrapper(array);
        assertArrayEquals(array, wrapper.getArray());
    }
    
    @Test
    void listWrapping() {
        final int[] first = new int[]{1, 2, 3};
        final int[] second = new int[]{1, 2, 3, 4};
        final List<IntArrayWrapper> wrappedArrays = IntArrayWrapper.wrapToList(Arrays.asList(first, second));
        
        assertEquals(2, wrappedArrays.size());
        assertArrayEquals(first, wrappedArrays.get(0).getArray());
        assertArrayEquals(second, wrappedArrays.get(1).getArray());
    }
    
    @Test
    void setWrapping() {
        final int[] first = new int[]{1, 2, 3};
        final int[] second = new int[]{1, 2, 3, 4};
        final Set<IntArrayWrapper> wrappedArrays = IntArrayWrapper.wrapToSet(new HashSet<>(Arrays.asList(first, second)));
        
        assertEquals(2, wrappedArrays.size());
        assertTrue(wrappedArrays.contains(new IntArrayWrapper(first)));
        assertTrue(wrappedArrays.contains(new IntArrayWrapper(second)));
    }
    
    @Test
    @SuppressWarnings("SimplifiableJUnitAssertion")
    void equalsAndHashCode() {
        final int[] firstArray = new int[]{1, 2, 3};
        final int[] secondArray = new int[]{1, 2, 3};
        final IntArrayWrapper firstWrapper = new IntArrayWrapper(firstArray);
        final IntArrayWrapper secondWrapper = new IntArrayWrapper(secondArray);
        
        assertTrue(firstWrapper.equals(secondWrapper));
        assertEquals(firstWrapper.hashCode(), secondWrapper.hashCode());
    }
    
}
