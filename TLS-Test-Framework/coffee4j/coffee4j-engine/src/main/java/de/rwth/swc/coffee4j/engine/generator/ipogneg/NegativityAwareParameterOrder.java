package de.rwth.swc.coffee4j.engine.generator.ipogneg;

import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.generator.ipog.ParameterOrder;
import de.rwth.swc.coffee4j.engine.util.ArrayUtil;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.Int2IntMap;

import java.util.Arrays;

class NegativityAwareParameterOrder implements ParameterOrder {
    
    private final int[] negativeParameters;
    
    NegativityAwareParameterOrder(TupleList forbiddenTuples) {
        Preconditions.notNull(forbiddenTuples);
        
        negativeParameters = forbiddenTuples.getInvolvedParameters();
    }
    
    @Override
    public int[] getInitialParameters(Int2IntMap parameters, int strength) {
        return Arrays.copyOf(negativeParameters, negativeParameters.length);
    }
    
    @Override
    public int[] getRemainingParameters(Int2IntMap parameters, int strength) {
        return ArrayUtil.exclude(parameters.keySet().toIntArray(), negativeParameters);
    }
    
}
