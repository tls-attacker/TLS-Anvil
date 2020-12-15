package de.rwth.swc.coffee4j.engine.generator.ipog;

import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.Int2IntMap;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import it.unimi.dsi.fastutil.ints.IntSet;

import java.util.*;

import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.NO_VALUE;
import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.containsAllParameters;

/**
 * This acts as the coverage map described in section 4.1 of the paper
 * "An Efficient Design and Implementation of the In-Parameter-Order Algorithm".
 * Basically, it stores the tuples of each possible ParameterCombination as a
 * bitmap with a bijective function to map to and from an index in said bitmap.
 * <p>
 * This uses the index system described in {@link IpogAlgorithm}.
 */
public class EfficientCoverageMap implements CoverageMap {
    
    private static final String PARAMETER_COMBINATIONS_NOT_NULL = "Parameter combinations must not be null";
    private static final String PARAMETER_NOT_VALID = "The parameter index must not be negative";
    private static final String FIXED_PARAMETER_NOT_CONTAINED = "The fixed parameter has to be contained in the " + "parameter map";
    private static final String COMBINATION_NOT_NULL = "Combination cannot be null";
    private static final String PARAMETERS_NOT_NULL = "Parameters cannot be null";
    
    private final int fixedParameter;
    private final int fixedParameterSize;
    
    private final Map<IntSet, ParameterCombinationCoverageMap> combinationCoverageMap = new HashMap<>();
    
    private final ConstraintChecker constraintChecker;
    
    /**
     * Initializes a new coverage map with the given parameter combinations
     * and the fixed parameter. This means that internally the fixed parameter
     * is added to each parameter combination.
     *
     * @param parameterCombinations the parameter combinations for which the
     *                              tuple coverage shall be tracked.
     *                              Must not be {@code null}
     * @param fixedParameter        the parameter added to all parameters.
     *                              Must not be negative
     * @param parameters            the sizes of all parameter. Must contains the sizes
     *                              of the parameters in all combinations and the fixed
     *                              parameter. Must not be {@code null}
     * @param constraintChecker     ConstraintChecker to identify irrelevant combinations
     * @throws NullPointerException     if parameterCombinations or parameters
     *                                  is {@code null}
     * @throws IllegalArgumentException if one of the other constraints
     *                                  described for each method parameter
     *                                  is not met
     */
    public EfficientCoverageMap(Collection<IntSet> parameterCombinations, int fixedParameter, Int2IntMap parameters,
                                ConstraintChecker constraintChecker) {
        Preconditions.notNull(parameterCombinations, PARAMETER_COMBINATIONS_NOT_NULL);
        Preconditions.notNull(parameters, PARAMETERS_NOT_NULL);
        Preconditions.check(fixedParameter >= 0, PARAMETER_NOT_VALID);
        Preconditions.check(parameters.containsKey(fixedParameter), FIXED_PARAMETER_NOT_CONTAINED);
        Preconditions.notNull(constraintChecker);
        
        this.constraintChecker = constraintChecker;
        this.fixedParameter = fixedParameter;
        fixedParameterSize = parameters.get(fixedParameter);
        constructCombinationCoverageMap(parameterCombinations, fixedParameter, parameters);
    }
    
    private void constructCombinationCoverageMap(Collection<IntSet> parameterCombinations,
                                                 int fixedParameter,
                                                 Int2IntMap parameters) {
        if (parameterCombinations.isEmpty()) {
            parameterCombinations = Collections.singleton(new IntOpenHashSet(0));
        }
        
        for (IntSet parameterCombination : parameterCombinations) {
            combinationCoverageMap.put(
                    parameterCombination,
                    new ParameterCombinationCoverageMap(
                            parameterCombination,
                            fixedParameter,
                            parameters,
                            constraintChecker));
        }
    }
    
    /**
     * @return whether any combination is not covered
     */
    @Override
    public boolean mayHaveUncoveredCombinations() {
        for (ParameterCombinationCoverageMap combinationCoverage : combinationCoverageMap.values()) {
            if (combinationCoverage.mayHaveUncoveredCombinations()) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Marks all sub-combinations which can be mapped to one of the given
     * parameter combinations given in the constructor as covered.
     *
     * @param combination the combination to mark as covered.
     *                    Must not be {@code null}
     * @throws NullPointerException if combination is {@code null}
     */
    @Override
    public void markAsCovered(int[] combination) {
        Preconditions.notNull(combination, COMBINATION_NOT_NULL);
        
        if (combination[fixedParameter] != NO_VALUE) {
            Set<ParameterCombinationCoverageMap> relevantCombinationCoverages
                    = getRelevantCombinationCoverages(combination);

            for (ParameterCombinationCoverageMap combinationCoverage : relevantCombinationCoverages) {
                combinationCoverage.markAsCovered(combination);
            }
        }
    }
    
    private Set<ParameterCombinationCoverageMap> getRelevantCombinationCoverages(int[] combination) {
        Set<ParameterCombinationCoverageMap> relevantCombinationCoverages = new HashSet<>();
        for (Map.Entry<IntSet, ParameterCombinationCoverageMap> entry : combinationCoverageMap.entrySet()) {
            if (containsAllParameters(combination, entry.getKey())) {
                relevantCombinationCoverages.add(entry.getValue());
            }
        }
        
        return relevantCombinationCoverages;
    }
    
    /**
     * Computes the number of combinations which would be covered if the fixed
     * parameter given in the constructor would be set to a specific value in
     * the given combination.
     *
     * @param combination the base combination in which the gains of the values
     *                    for the fixed parameter shall be computed.
     *                    Must not be {@code null}
     * @return the number of combinations which would additionally be covered
     * if the fixed parameter was set to a certain value. The index
     * in the array corresponds to the value index in the parameter
     * <p>
     * the index is -1 if it refers to an invalid combination
     * Please note: only t-wise invalid combinations are identified!
     * The test input must be checked as well for {@literal k>t}-wise invalid combinations
     * @throws NullPointerException if combination is {@code null}
     */
    @Override
    public int[] computeGainsOfFixedParameter(int[] combination) {
        Preconditions.notNull(combination, COMBINATION_NOT_NULL);
        
        int[] gains = new int[fixedParameterSize];
        Set<ParameterCombinationCoverageMap> relevantCombinations = getRelevantCombinationCoverages(combination);
        for (ParameterCombinationCoverageMap combinationCoverage : relevantCombinations) {
            combinationCoverage.addGainsOfFixedParameter(combination, gains);
        }
        
        return gains;
    }
    
    /**
     * Finds the next uncovered combination and returns it.
     *
     * @return the next uncovered combination in all parameter combination
     * coverage maps or an empty {@link Optional} if no combination is
     * uncovered
     */
    @Override
    public Optional<int[]> getUncoveredCombination() {
        for (ParameterCombinationCoverageMap combinationCoverage : combinationCoverageMap.values()) {
            if (combinationCoverage.mayHaveUncoveredCombinations()) {
                final Optional<int[]> uncoveredCombination = combinationCoverage.getUncoveredCombination();

                if(uncoveredCombination.isPresent()) {
                    return uncoveredCombination;
                }
            }
        }
        
        return Optional.empty();
    }
}
