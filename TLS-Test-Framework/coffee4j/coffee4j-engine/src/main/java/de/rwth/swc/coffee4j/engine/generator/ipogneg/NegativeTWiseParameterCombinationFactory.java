package de.rwth.swc.coffee4j.engine.generator.ipogneg;

import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.generator.ipog.ParameterCombinationFactory;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.IntSet;

import java.util.List;

import static de.rwth.swc.coffee4j.engine.util.Combinator.computeNegativeParameterCombinations;

class NegativeTWiseParameterCombinationFactory implements ParameterCombinationFactory {
    
    private final int[] negativeParameters;
    
    NegativeTWiseParameterCombinationFactory(TupleList forbiddenTuples) {
        negativeParameters = Preconditions.notNull(forbiddenTuples).getInvolvedParameters();
    }
    
    @Override
    public List<IntSet> create(int[] oldParameters, int strength) {
        return computeNegativeParameterCombinations(oldParameters, negativeParameters, strength - 1);
    }
}