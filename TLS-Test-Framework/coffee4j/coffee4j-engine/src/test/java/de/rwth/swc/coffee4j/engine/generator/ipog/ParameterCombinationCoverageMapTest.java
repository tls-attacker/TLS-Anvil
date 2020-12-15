package de.rwth.swc.coffee4j.engine.generator.ipog;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory;
import it.unimi.dsi.fastutil.ints.Int2IntMap;
import it.unimi.dsi.fastutil.ints.Int2IntOpenHashMap;
import it.unimi.dsi.fastutil.ints.IntSet;
import it.unimi.dsi.fastutil.ints.IntSets;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class ParameterCombinationCoverageMapTest {

    @Test
    void testUncoveredCombination() {
        final TestModel testModel = new TestModel(1, new int[] { 3, 3, 3}, Collections.emptyList(), List.of(
                new TupleList(1, new int[] { 0 }, List.of(new int[] { 2 })),
                new TupleList(2, new int[] { 1 }, List.of(new int[] { 2 })),
                new TupleList(3, new int[] { 2 }, List.of(new int[] { 2 }))
        ));

        final ConstraintChecker constraintChecker = new HardConstraintCheckerFactory()
                .createConstraintChecker(testModel);

        final IntSet parameterCombination = IntSets.EMPTY_SET;
        final int fixedParameter = 1;
        final Int2IntMap parameters = new Int2IntOpenHashMap();
        parameters.put(0, 3);
        parameters.put(1, 3);
        parameters.put(2, 3);

        final ParameterCombinationCoverageMap coverageMap = new ParameterCombinationCoverageMap(
                parameterCombination, fixedParameter, parameters, constraintChecker);

        assertTrue(coverageMap.mayHaveUncoveredCombinations());
        assertTrue(coverageMap.getUncoveredCombination().isPresent());
    }

    @Test
    void testOnlyUncoveredCombinationIsForbidden() {
        final TestModel testModel = new TestModel(1, new int[] { 3, 3, 3}, Collections.emptyList(), List.of(
                new TupleList(1, new int[] { 0 }, List.of(new int[] { 2 })),
                new TupleList(2, new int[] { 1 }, List.of(new int[] { 2 })),
                new TupleList(3, new int[] { 2 }, List.of(new int[] { 2 }))
        ));

        final ConstraintChecker constraintChecker = new HardConstraintCheckerFactory()
                .createConstraintChecker(testModel);

        final IntSet parameterCombination = IntSets.EMPTY_SET;
        final int fixedParameter = 1;
        final Int2IntMap parameters = new Int2IntOpenHashMap();
        parameters.put(0, 3);
        parameters.put(1, 3);
        parameters.put(2, 3);

        final ParameterCombinationCoverageMap coverageMap = new ParameterCombinationCoverageMap(
                parameterCombination, fixedParameter, parameters, constraintChecker);
        coverageMap.markAsCovered(new int[] { 0, 0, -1 });
        coverageMap.markAsCovered(new int[] { 1, 1, -1 });

        assertTrue(coverageMap.mayHaveUncoveredCombinations());
        assertTrue(coverageMap.getUncoveredCombination().isEmpty());
        assertFalse(coverageMap.mayHaveUncoveredCombinations());
    }

    @Test
    void testWithUncoveredCombinationIsForbidden() {
        final TestModel testModel = new TestModel(1, new int[] { 3, 3, 3}, Collections.emptyList(), List.of(
                new TupleList(1, new int[] { 0 }, List.of(new int[] { 1 })),
                new TupleList(2, new int[] { 1 }, List.of(new int[] { 1 })),
                new TupleList(3, new int[] { 2 }, List.of(new int[] { 1 }))
        ));

        final ConstraintChecker constraintChecker = new HardConstraintCheckerFactory()
                .createConstraintChecker(testModel);

        final IntSet parameterCombination = IntSets.EMPTY_SET;
        final int fixedParameter = 1;
        final Int2IntMap parameters = new Int2IntOpenHashMap();
        parameters.put(0, 3);
        parameters.put(1, 3);
        parameters.put(2, 3);

        final ParameterCombinationCoverageMap coverageMap = new ParameterCombinationCoverageMap(
                parameterCombination, fixedParameter, parameters, constraintChecker);
        coverageMap.markAsCovered(new int[] { 0, 0, -1 });

        assertTrue(coverageMap.mayHaveUncoveredCombinations());

        Optional<int[]> uncoveredCombination = coverageMap.getUncoveredCombination();
        assertTrue(uncoveredCombination.isPresent());
        assertArrayEquals(new int[] { -1, 2, -1}, uncoveredCombination.get());
    }

}
