package de.rwth.swc.coffee4j.engine.generator.ipog;

import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import it.unimi.dsi.fastutil.ints.Int2IntMap;
import it.unimi.dsi.fastutil.ints.IntSet;

import java.util.Arrays;
import java.util.BitSet;
import java.util.Optional;

import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.NO_VALUE;

/**
 * This acts as a partial coverage map for one parameter combination.
 *
 * See {@link EfficientCoverageMap EfficientCoverageMap} and section 4.1 of the paper
 * "An Efficient Design and Implementation of the In-Parameter-Order Algorithm" for more information.
 */
final class ParameterCombinationCoverageMap {

    private final int numberOfCombinations;
    private final int numberOfParameters;

    private final int[] parameterCombination;
    private final int[] parameterSizes;
    private final int[] parameterMultipliers;

    private final BitSet coverageMap;

    private final ConstraintChecker constraintChecker;

    /**
     * Initializes a new ParameterCombinationCoverageMap.
     *
     * @param parameterCombination  the parameter combinations for which the
     *      *                       tuple coverage shall be tracked.
     *      *                       Must not be {@code null}
     * @param fixedParameter        the parameter added to all parameters.
     *                              Must not be negative
     * @param parameters            the sizes of all parameter. Must contains the sizes
     *                              of the parameters in all combinations and the fixed
     *                              parameter. Must not be {@code null}
     * @param constraintChecker     ConstraintChecker to identify irrelevant combinations
     */
    ParameterCombinationCoverageMap(IntSet parameterCombination,
                                    int fixedParameter,
                                    Int2IntMap parameters,
                                    ConstraintChecker constraintChecker) {
        this.parameterCombination = new int[parameterCombination.size() + 1];
        parameterCombination.toArray(this.parameterCombination);
        this.parameterCombination[parameterCombination.size()] = fixedParameter;
        parameterSizes = parameterSizesAsArray(parameters);
        parameterMultipliers = parameterMultipliersAsArray();

        numberOfCombinations = numberOfCombinations();
        numberOfParameters = parameters.size();

        coverageMap = new BitSet(numberOfCombinations);

        this.constraintChecker = constraintChecker;
    }

    private int[] parameterSizesAsArray(Int2IntMap parameters) {
        int[] parameterSizesAsArray = new int[parameterCombination.length];
        for (int i = 0; i < parameterCombination.length; i++) {
            parameterSizesAsArray[i] = parameters.get(parameterCombination[i]);
        }
        return parameterSizesAsArray;
    }

    private int[] parameterMultipliersAsArray() {
        int[] parameterMultipliersAsArray = new int[parameterSizes.length];
        int currentMultiplier = 1;
        for (int i = 0; i < parameterSizes.length; i++) {
            parameterMultipliersAsArray[i] = currentMultiplier;
            currentMultiplier *= parameterSizes[i];
        }
        return parameterMultipliersAsArray;
    }

    private int numberOfCombinations() {
        int count = 1;
        for (int parameterSize : parameterSizes) {
            count *= parameterSize;
        }
        return count;
    }

    /**
     * Checks if uncovered combinations may exist.
     * Please note, combinations may be uncovered but at the same forbidden by constraints.
     * There is no guarantee that there is a combination that is uncovered and relevant.
     *
     * @return  true if at least one combination is uncovered
     *          false if all combinations are covered
     */
    boolean mayHaveUncoveredCombinations() {
        return coverageMap.cardinality() < numberOfCombinations;
    }

    /**
     * Marks a combination as covered.
     * The method has no effect if the combination was already covered.
     *
     * @param combination   combination to mark as covered
     */
    void markAsCovered(int[] combination) {
        int index = getIndexUntil(combination, parameterCombination.length);

        if (!coverageMap.get(index)) {
            markIndexAsCovered(index);
        }
    }

    private void markIndexAsCovered(int index) {
        coverageMap.set(index);
    }

    private int getIndexUntil(int[] combination, int parameterCount) {
        int index = 0;
        for (int i = 0; i < parameterCount; i++) {
            int parameter = parameterCombination[i];
            index += combination[parameter] * parameterMultipliers[i];
        }
        return index;
    }

    /**
     * Computes an uncovered combination if an uncovered combination exists.
     * Please note that even if there may be uncovered combinations according to {@link #mayHaveUncoveredCombinations() mayHaveUncoveredCombinations()},
     * this method can still return an empty {@link Optional} when all uncovered combinations are forbidden by constraints.
     *
     * @return  an optional that may contain an uncovered combination
     */
    Optional<int[]> getUncoveredCombination() {
        if(!mayHaveUncoveredCombinations()) {
            return Optional.empty();
        }

        final int index = coverageMap.nextClearBit(0);

        if(index >= numberOfCombinations) {
            throw new IllegalStateException("corrupt invariant");
        }

        final int[] uncoveredCombination = getCombination(index);

        if(constraintChecker.isValid(uncoveredCombination)) {
            return Optional.of(uncoveredCombination);
        } else {
            markAsCovered(uncoveredCombination);

            if(mayHaveUncoveredCombinations()) {
                return getUncoveredCombination();
            } else {
                return Optional.empty();
            }
        }
    }

    private int[] getCombination(int index) {
        int[] combination = new int[numberOfParameters];
        Arrays.fill(combination, NO_VALUE);

        for (int i = parameterCombination.length - 1; i >= 0; i--) {
            int parameter = parameterCombination[i];
            int parameterIndexPart = (index - (index % parameterMultipliers[i]));
            int value = parameterIndexPart / parameterMultipliers[i];
            combination[parameter] = value;
            index -= parameterIndexPart;
        }

        return combination;
    }

    void addGainsOfFixedParameter(int[] combination, int[] gains) {
        if (!mayHaveUncoveredCombinations()) {
            return;
        }

        int fixedParameterIndex = parameterCombination.length - 1;
        int baseIndex = getIndexUntil(combination, fixedParameterIndex);

        int[] subset = createSubsetOfCombination(combination, parameterCombination);

        for (int value = 0; value < gains.length; value++) {
            int index = baseIndex + value * parameterMultipliers[fixedParameterIndex];

            if (gains[value] != -1 && !coverageMap.get(index)) {
                subset[fixedParameterIndex] = value;

                if (constraintChecker.isDualValid(parameterCombination, subset)) {
                    gains[value]++;
                } else {
                    markIndexAsCovered(index);
                    gains[value] = -1;
                }
            }
        }
    }

    private int[] createSubsetOfCombination(int[] combination, int[] parameters) {
        int[] subset = new int[parameters.length];

        for (int i = 0; i < subset.length; i++) {
            subset[i] = combination[parameters[i]];
        }

        return subset;
    }
}
