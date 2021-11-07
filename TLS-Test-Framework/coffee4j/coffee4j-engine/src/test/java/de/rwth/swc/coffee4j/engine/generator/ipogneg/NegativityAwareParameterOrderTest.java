package de.rwth.swc.coffee4j.engine.generator.ipogneg;

import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.generator.ipog.ParameterOrder;
import it.unimi.dsi.fastutil.ints.Int2IntArrayMap;
import it.unimi.dsi.fastutil.ints.Int2IntMap;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;


class NegativityAwareParameterOrderTest {
    
    @Test
    void testInitialParametersForSingleNegativeParameter() {
        ParameterOrder parameterOrder = negativityAwareParameterOrder(1, new int[]{0});
        
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        int[] initialParameters = parameterOrder.getInitialParameters(parameters, 0);
        
        assertEquals(initialParameters.length, 1);
        assertArrayEquals(initialParameters, new int[]{0});
    }
    
    @Test
    void testInitialParametersForTwoNegativeParameters() {
        ParameterOrder parameterOrder = negativityAwareParameterOrder(1, new int[]{1, 2});
        
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        int[] initialParameters = parameterOrder.getInitialParameters(parameters, 0);
        
        assertEquals(initialParameters.length, 2);
        assertArrayEquals(initialParameters, new int[]{1, 2});
    }
    
    @Test
    void testInitialParametersForAllNegativeParameters() {
        ParameterOrder parameterOrder = negativityAwareParameterOrder(1, new int[]{0, 1, 2, 3});
        
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        int[] initialParameters = parameterOrder.getInitialParameters(parameters, 0);
        
        assertEquals(initialParameters.length, 4);
        assertArrayEquals(initialParameters, new int[]{0, 1, 2, 3});
    }
    
    @Test
    void testRemainingParametersForSingleNegativeParameter() {
        ParameterOrder parameterOrder = negativityAwareParameterOrder(1, new int[]{0});
        
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        
        int[] remainingParameters = parameterOrder.getRemainingParameters(parameters, 0);
        
        assertEquals(3, remainingParameters.length);
        assertArrayEquals(new int[]{1, 2, 3}, remainingParameters);
    }
    
    @Test
    void testRemainingParametersForTwoNegativeParameter() {
        ParameterOrder parameterOrder = negativityAwareParameterOrder(1, new int[]{1, 3});
        
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        
        int[] remainingParameters = parameterOrder.getRemainingParameters(parameters, 0);
        
        assertEquals(2, remainingParameters.length);
        assertArrayEquals(new int[]{0, 2}, remainingParameters);
    }
    
    @Test
    void testRemainingParametersForAllNegativeParameter() {
        ParameterOrder parameterOrder = negativityAwareParameterOrder(1, new int[]{0, 1, 2, 3});
        
        Int2IntMap parameters = new Int2IntArrayMap(new int[]{0, 1, 2, 3}, new int[]{2, 2, 2, 2});
        
        int[] remainingParameters = parameterOrder.getRemainingParameters(parameters, 0);
        
        assertEquals(0, remainingParameters.length);
        assertArrayEquals(new int[]{}, remainingParameters);
    }
    
    private ParameterOrder negativityAwareParameterOrder(int id, int[] negativeParameters) {
        final TupleList forbiddenTuples = new TupleList(id, negativeParameters, Collections.singletonList(negativeParameters));
        
        return new NegativityAwareParameterOrder(forbiddenTuples);
    }
}
