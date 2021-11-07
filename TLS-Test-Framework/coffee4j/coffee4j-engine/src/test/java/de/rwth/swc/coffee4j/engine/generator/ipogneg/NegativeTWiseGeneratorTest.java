package de.rwth.swc.coffee4j.engine.generator.ipogneg;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintViolationAssertions;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import de.rwth.swc.coffee4j.engine.report.StandardOutputReporter;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

interface NegativeTWiseGeneratorTest {
    
    TestInputGroupGenerator getGenerator();
    
    @Test
    default void onlyErrorTuplesAppear() {
        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0, 1}, Arrays.asList(new int[]{0, 0})));
        errorTupleLists.add(new TupleList(2, new int[]{1, 2}, Arrays.asList(new int[]{1, 1})));
        
        final TestModel model = new TestModel(2, new int[]{2, 2, 2, 2}, Collections.emptyList(), errorTupleLists);
        
        final TestInputGroupGenerator generator = getGenerator();
        final List<TestInputGroup> testInputGroups = generator.generate(model, new StandardOutputReporter()).stream().map(Supplier::get).collect(Collectors.toList());
        assertEquals(2, testInputGroups.size());
        
        assertEquals(errorTupleLists.get(0), testInputGroups.get(0).getIdentifier());
        List<int[]> firstTestInputs = testInputGroups.get(0).getTestInputs();
        assertFalse(firstTestInputs.isEmpty());
        assertTrue(firstTestInputs.stream().allMatch(testInput -> CombinationUtil.contains(testInput, new int[]{0, 0, -1, -1})));
        
        assertEquals(errorTupleLists.get(1), testInputGroups.get(1).getIdentifier());
        List<int[]> secondTestInputs = testInputGroups.get(1).getTestInputs();
        assertFalse(secondTestInputs.isEmpty());
        assertTrue(secondTestInputs.stream().allMatch(testInput -> CombinationUtil.contains(testInput, new int[]{-1, 1, 1, -1})));
    }
    
    @Test
    default void testImplicitConflictsDoNotAppear() {
        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0, 1}, Arrays.asList(new int[]{0, 0}, new int[]{1, 1})));
        errorTupleLists.add(new TupleList(2, new int[]{1, 2}, Arrays.asList(new int[]{1, 1})));
        
        final TestModel model = new TestModel(2, new int[]{2, 2, 2, 2}, Collections.emptyList(), errorTupleLists);
        
        final TestInputGroupGenerator generator = getGenerator();
        final List<TestInputGroup> testInputGroups = generator.generate(model, new StandardOutputReporter()).stream().map(Supplier::get).collect(Collectors.toList());
        assertEquals(2, testInputGroups.size());
        
        assertEquals(errorTupleLists.get(0), testInputGroups.get(0).getIdentifier());
        final List<int[]> firstTestInputs = testInputGroups.get(0).getTestInputs();
        assertTrue(firstTestInputs.stream().allMatch(testInput -> CombinationUtil.contains(testInput, new int[]{0, 0, -1, -1}) || CombinationUtil.contains(testInput, new int[]{1, 1, -1, -1})));
        assertTrue(firstTestInputs.stream().anyMatch(testInput -> CombinationUtil.contains(testInput, new int[]{0, 0, -1, -1})));
        assertTrue(firstTestInputs.stream().anyMatch(testInput -> CombinationUtil.contains(testInput, new int[]{1, 1, -1, -1})));
        
        assertEquals(errorTupleLists.get(1), testInputGroups.get(1).getIdentifier());
        final List<int[]> secondTestInputs = testInputGroups.get(1).getTestInputs();
        assertTrue(secondTestInputs.stream().allMatch(testInput -> CombinationUtil.contains(testInput, new int[]{-1, 1, 1, -1})));
    }
    
    @Test
    default void testConflictsDoAppear() {
        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{1}, Arrays.asList(new int[]{2})));
        errorTupleLists.add(new TupleList(2, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2}, new int[]{1, 0}, new int[]{1, 2})));
        errorTupleLists.add(new TupleList(3, new int[]{2}, Arrays.asList(new int[]{2})));
        final TestModel model = new TestModel(2, new int[]{2, 3, 3}, Collections.emptyList(), errorTupleLists);
        
        final TestInputGroupGenerator generator = getGenerator();
        final List<TestInputGroup> testInputGroups = generator.generate(model, new StandardOutputReporter()).stream().map(Supplier::get).collect(Collectors.toList());
        assertEquals(3, testInputGroups.size());
        
        assertEquals(errorTupleLists.get(0), testInputGroups.get(0).getIdentifier());
        final List<int[]> firstTestInputs = testInputGroups.get(0).getTestInputs();
        assertFalse(firstTestInputs.isEmpty());
        assertTrue(firstTestInputs.stream().allMatch(testInput -> CombinationUtil.contains(testInput, new int[]{-1, 2, -1})));
        
        assertEquals(errorTupleLists.get(1), testInputGroups.get(1).getIdentifier());
        final List<int[]> secondTestInputs = testInputGroups.get(1).getTestInputs();
        assertFalse(secondTestInputs.isEmpty());
        assertTrue(secondTestInputs.stream().allMatch(testInput -> CombinationUtil.contains(testInput, new int[]{0, 1, -1}) || CombinationUtil.contains(testInput, new int[]{1, 0, -1}) || CombinationUtil.contains(testInput, new int[]{0, 2, -1}) || CombinationUtil.contains(testInput, new int[]{1, 2, -1})));
        assertTrue(secondTestInputs.stream().anyMatch(testInput -> CombinationUtil.contains(testInput, new int[]{0, 1, -1})));
        assertTrue(secondTestInputs.stream().anyMatch(testInput -> CombinationUtil.contains(testInput, new int[]{1, 0, -1})));
        assertTrue(secondTestInputs.stream().anyMatch(testInput -> CombinationUtil.contains(testInput, new int[]{0, 2, -1})));
        assertTrue(secondTestInputs.stream().anyMatch(testInput -> CombinationUtil.contains(testInput, new int[]{1, 2, -1})));
    }
    
    @Test
    default void testErrorConstraintAndOneUnsatisfied() {
        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{1}, Arrays.asList(new int[]{2})));
        errorTupleLists.add(new TupleList(2, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2}, new int[]{1, 0}, new int[]{1, 2})));
        errorTupleLists.add(new TupleList(3, new int[]{2}, Arrays.asList(new int[]{2})));
        
        final TestModel model = new TestModel(2, new int[]{2, 3, 3}, Collections.emptyList(), errorTupleLists);
        
        final TestInputGroupGenerator generator = getGenerator();
        final List<TestInputGroup> testInputGroups = generator.generate(model, new StandardOutputReporter()).stream().map(Supplier::get).collect(Collectors.toList());
        assertEquals(3, testInputGroups.size());
        
        for (TestInputGroup group : testInputGroups) {
            for (int[] tuple : group.getTestInputs()) {
                ConstraintViolationAssertions.assertNoExclusionConstraintViolations(model, tuple);
                ConstraintViolationAssertions.assertAtMostNumberOfErrorConstraintViolations(model, tuple, 2);
            }
        }
    }
    
}
