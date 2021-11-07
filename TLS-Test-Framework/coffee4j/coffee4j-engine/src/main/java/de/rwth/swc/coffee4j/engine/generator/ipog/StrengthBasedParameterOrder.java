package de.rwth.swc.coffee4j.engine.generator.ipog;

import it.unimi.dsi.fastutil.ints.Int2IntMap;

import java.util.stream.IntStream;

/**
 * A parameter order based on the normal parameter order and the testing strength. The initial parameters are the first
 * t parameters if t is the testing strength, and all other parameters are returned separately.
 * This means parameters 1, 2, 3, 4, 5 get split into initial 1, 2 and remaining 3, 4, 5 if testing strength = 2.
 */
public class StrengthBasedParameterOrder implements ParameterOrder {
    
    @Override
    public int[] getInitialParameters(Int2IntMap parameters, int strength) {
        int size = Math.min(parameters.size(), strength);
        
        return IntStream.range(0, size).toArray();
    }
    
    @Override
    public int[] getRemainingParameters(Int2IntMap parameters, int strength) {
        return IntStream.range(strength, parameters.size()).toArray();
    }
    
}
