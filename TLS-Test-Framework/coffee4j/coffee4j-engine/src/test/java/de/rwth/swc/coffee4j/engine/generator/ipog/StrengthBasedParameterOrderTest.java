package de.rwth.swc.coffee4j.engine.generator.ipog;

import it.unimi.dsi.fastutil.ints.Int2IntArrayMap;
import it.unimi.dsi.fastutil.ints.Int2IntMap;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;


class StrengthBasedParameterOrderTest {
    
    private static final ParameterOrder PARAMETER_ORDER = new StrengthBasedParameterOrder();
    
    @Test
    void testInitialParametersForSmallerStrength() {
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        int strength = 2;
        
        int[] initialParameters = PARAMETER_ORDER.getInitialParameters(parameters, strength);
        
        assertEquals(initialParameters.length, 2);
        assertArrayEquals(initialParameters, new int[]{0, 1});
    }
    
    @Test
    void testInitialParametersForEqualStrength() {
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        int strength = 4;
        
        int[] initialParameters = PARAMETER_ORDER.getInitialParameters(parameters, strength);
        
        assertEquals(initialParameters.length, 4);
        assertArrayEquals(initialParameters, new int[]{0, 1, 2, 3});
    }
    
    @Test
    void testInitialParametersForHigherStrength() {
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        int strength = 5;
        
        int[] initialParameters = PARAMETER_ORDER.getInitialParameters(parameters, strength);
        
        assertEquals(4, initialParameters.length);
        assertArrayEquals(new int[]{0, 1, 2, 3}, initialParameters);
    }
    
    @Test
    void testRemainingParametersForSmallerStrength() {
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        int strength = 2;
        
        int[] remainingParameters = PARAMETER_ORDER.getRemainingParameters(parameters, strength);
        
        assertEquals(2, remainingParameters.length);
        assertArrayEquals(new int[]{2, 3}, remainingParameters);
    }
    
    @Test
    void testRemainingParametersForEqualStrength() {
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        int strength = 4;
        
        int[] remainingParameters = PARAMETER_ORDER.getRemainingParameters(parameters, strength);
        
        assertEquals(remainingParameters.length, 0);
        assertArrayEquals(remainingParameters, new int[]{});
        
    }
    
    @Test
    void testRemainingParametersForHigherStrength() {
        
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        int strength = 5;
        
        int[] remainingParameters = PARAMETER_ORDER.getRemainingParameters(parameters, strength);
        
        assertEquals(remainingParameters.length, 0);
        assertArrayEquals(remainingParameters, new int[]{});
    }
}
