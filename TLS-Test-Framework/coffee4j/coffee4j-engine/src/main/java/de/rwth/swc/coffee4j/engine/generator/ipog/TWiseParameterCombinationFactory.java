package de.rwth.swc.coffee4j.engine.generator.ipog;

import it.unimi.dsi.fastutil.ints.IntSet;

import java.util.Collections;
import java.util.List;

import static de.rwth.swc.coffee4j.engine.util.Combinator.computeParameterCombinations;

/**
 * The "normal" strategy for covering all t-value-combinations for combinatorial test with testing strength t.
 * This means that all combinations of previous parameters with strength t - 1 are returned, as the current parameter
 * is added to every combination as described in {@link ParameterCombinationFactory}.
 */
public class TWiseParameterCombinationFactory implements ParameterCombinationFactory {
    
    @Override
    public List<IntSet> create(int[] oldParameters, int strength) {
        return computeParameterCombinations(oldParameters, strength - 1);
    }
}
