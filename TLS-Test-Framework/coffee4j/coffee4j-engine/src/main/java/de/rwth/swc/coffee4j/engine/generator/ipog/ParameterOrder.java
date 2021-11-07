package de.rwth.swc.coffee4j.engine.generator.ipog;

import it.unimi.dsi.fastutil.ints.Int2IntMap;

/**
 * Defines the order in which parameters should be covered in IPOG. The order can be relevant for performance and test
 * suite size. Additionally, a correct combination of order and {@link ParameterCombinationFactory} can be important.
 */
public interface ParameterOrder {
    
    /**
     * All combinations which should be used in the first initial step of IPOG. In this step the cartesian product of
     * all returned parameters is calculated. This means that the strength may need to be considered.
     *
     * @param parameters the parameters and their sizes.
     * @param strength   with which the test suite should be calculated
     * @return all parameters which should be constructed using the combinatorial product. This explicitly means that
     * these parameters are always in oldParameters in a {@link ParameterCombinationFactory}
     */
    int[] getInitialParameters(Int2IntMap parameters, int strength);
    
    /**
     * The order of all remaining parameters. The parameter which should be expanded in the first horizontal expansion
     * should be at the first place in the array (index 0).
     *
     * @param parameters the parameters and their sizes.
     * @param strength   with which the test suite should be calculated
     * @return all parameters which were not already returned by {@link #getInitialParameters(Int2IntMap, int)}
     * and any order
     */
    int[] getRemainingParameters(Int2IntMap parameters, int strength);
    
}
