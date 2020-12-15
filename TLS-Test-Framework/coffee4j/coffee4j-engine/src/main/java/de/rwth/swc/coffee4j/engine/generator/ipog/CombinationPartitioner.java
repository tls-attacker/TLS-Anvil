package de.rwth.swc.coffee4j.engine.generator.ipog;

import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.Int2ObjectMap;
import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.NO_VALUE;
import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.add;
import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.canBeAdded;
import static de.rwth.swc.coffee4j.engine.util.IntArrayWrapper.wrap;

/**
 * Class to partition given combinations according to one parameter.
 * This is used to make the search for fitting combinations in the {@link IpogAlgorithm}
 * algorithm more efficient as only some potentially matching combinations
 * have to be searched for a match.
 * <p>
 * In all methods the indexing schema described in {@link IpogAlgorithm} is used.
 */
class CombinationPartitioner {
    
    private static final String COMBINATIONS_NOT_NULL = "Combinations must not be null";
    private static final String COMBINATION_NOT_NULL = "Combination must not be null";
    private static final String VALID_PARAMETER_INDEX = "The index of the parameter must be at least 0";
    private static final String VALID_NUMBER_OF_VALUES = "The number of values for a parameter must be greater than 0";
    private static final String PARAMETER_NOT_IN_COMBINATION = "The partitioning parameter is not in the combination";
    
    private final int partitioningParameter;
    private final Int2ObjectMap<HashSet<IntArrayWrapper>> partitioner;
    
    /**
     * Creates a new combination partitioner according to the given parameter.
     * This means that all given combinations are split according to the value
     * they have for the parameter. The value can either be one of the values
     * of the partitioning parameter or
     * {@link CombinationUtil#NO_VALUE},if the
     * value for the parameter is not set in this combination.
     *
     * @param combinations          the combinations to be partitioned. Must not be
     *                              {@code null} and all combinations must have at least
     *                              enough parameters so that the partitioning parameter
     *                              is contained and must not be {@code null}. At least
     *                              one combination must be given
     * @param partitioningParameter the parameter with which the combinations
     *                              will be split. Must not be smaller than
     *                              zero or larger than the size of the
     *                              combinations - 1
     * @param numberOfValues        the number of values of the partitioning parameter.
     *                              Must be greater than 0
     * @throws NullPointerException     if combinations is {@code null} or one of
     *                                  the contained combinations is {@code null}
     * @throws IllegalArgumentException if one of the other constraints for the
     *                                  method parameters is not met
     */
    CombinationPartitioner(Collection<int[]> combinations, int partitioningParameter, int numberOfValues) {
        Preconditions.notNull(combinations, COMBINATIONS_NOT_NULL);
        Preconditions.check(partitioningParameter >= 0, VALID_PARAMETER_INDEX);
        Preconditions.check(numberOfValues > 0, VALID_NUMBER_OF_VALUES);
        
        this.partitioningParameter = partitioningParameter;
        
        partitioner = new Int2ObjectOpenHashMap<>(numberOfValues + 1);
        for (int i = 0; i < numberOfValues; i++) {
            partitioner.put(i, new HashSet<>());
        }
        partitioner.put(NO_VALUE, new HashSet<>());
        
        for (int[] combination : combinations) {
            Preconditions.notNull(combination, COMBINATION_NOT_NULL);
            Preconditions.check(combination.length > partitioningParameter, PARAMETER_NOT_IN_COMBINATION);
            
            addCombination(combination);
        }
    }
    
    /**
     * Adds the given combination to the partition determined by the value
     * at the partitioning parameter.
     *
     * @param combination the combination to be added. Must not be {@code null}
     *                    and must contain the partitioning parameter
     * @throws NullPointerException     if combination is {@code null}
     * @throws IllegalArgumentException if the combination does not contain the
     *                                  partitioning parameter
     */
    void addCombination(int[] combination) {
        Preconditions.notNull(combination, COMBINATION_NOT_NULL);
        Preconditions.check(combination.length > partitioningParameter, PARAMETER_NOT_IN_COMBINATION);
        
        partitioner.get(combination[partitioningParameter]).add(wrap(combination));
    }
    
    /**
     * Removes the given combination from the partition determined by the value
     * at the partitioning parameter.
     *
     * @param combination the combination to be removed. Must not be
     *                    {@code null} and must contain the partitioning
     *                    parameter
     * @throws NullPointerException     if combination is {@code null}
     * @throws IllegalArgumentException if the combination does not contain the
     *                                  partitioning parameter
     */
    void removeCombination(int[] combination) {
        Preconditions.notNull(combination, COMBINATION_NOT_NULL);
        Preconditions.check(combination.length > partitioningParameter, PARAMETER_NOT_IN_COMBINATION);
        
        partitioner.get(combination[partitioningParameter]).remove(wrap(combination));
    }
    
    /**
     * Tries to find a matching combination to which the given combination
     * can be added. The potential matching combination is found by looking
     * only at combinations form partitions which can support the added
     * combination.
     *
     * @param combination the combination to be added to an existing
     *                    combination. Must not be {@code null} and must
     *                    contain the partitioning parameter
     * @return the combination to which the given combination has been added
     * or an empty {@link Optional} if no match could be found
     * @throws NullPointerException     if combination is {@code null}
     * @throws IllegalArgumentException if the combination does not contain the
     *                                  partitioning parameter
     */
    Optional<int[]> extendSuitableCombination(int[] combination, ConstraintChecker constraintChecker) {
        Preconditions.notNull(combination, COMBINATION_NOT_NULL);
        Preconditions.check(combination.length > partitioningParameter, PARAMETER_NOT_IN_COMBINATION);

        final List<IntArrayWrapper> possibleCombinations = new LinkedList<>(
                partitioner.get(combination[partitioningParameter]));
        possibleCombinations.addAll(partitioner.get(NO_VALUE));

        for (IntArrayWrapper possibleCombination : possibleCombinations) {
            if (tryToAdd(possibleCombination.getArray(), combination, constraintChecker)) {
                return Optional.of(possibleCombination.getArray());
            }
        }

        return Optional.empty();
    }

    private boolean tryToAdd(int[] baseCombination, int[] combinationToBeAdded, ConstraintChecker constraintChecker) {
        if (canBeAdded(baseCombination, combinationToBeAdded, constraintChecker)) {
            add(baseCombination, combinationToBeAdded);

            return true;
        } else {
            return false;
        }
    }
}