package de.rwth.swc.coffee4j.engine.generator.ipog;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class IpogAlgorithmWithConstraintsTest {
    
    @Test
    void checkWithSimpleConstraint() {
        final List<TupleList> forbiddenTupleLists = new ArrayList<>();
        forbiddenTupleLists.add(new TupleList(1, new int[]{0, 1}, Collections.singletonList(new int[]{1, 1})));
        forbiddenTupleLists.add(new TupleList(2, new int[]{1, 2}, Collections.singletonList(new int[]{1, 1})));
        
        final TestModel model = new TestModel(2, new int[]{2, 2, 2, 2}, forbiddenTupleLists, Collections.emptyList());
        
        final ConstraintChecker checker = new HardConstraintCheckerFactory().createConstraintChecker(model);
        
        final List<int[]> testSuite = new IpogAlgorithm(IpogConfiguration.ipogConfiguration().testModel(model).checker(checker).build()).generate();
        
        assertFalse(testSuite.stream().anyMatch((int[] test) -> CombinationUtil.contains(test, new int[]{1, 1, -1, -1})));
        assertFalse(testSuite.stream().anyMatch((int[] test) -> CombinationUtil.contains(test, new int[]{-1, 1, 1, -1})));
    }
    
    @Test
    void checkWithImplicitForbiddenTuple() {
        final List<TupleList> forbiddenTupleLists = new ArrayList<>();
        forbiddenTupleLists.add(new TupleList(1, new int[]{0, 1}, Arrays.asList(new int[]{0, 0}, new int[]{1, 1})));
        forbiddenTupleLists.add(new TupleList(2, new int[]{1, 2}, Collections.singletonList(new int[]{1, 1})));
        
        final TestModel model = new TestModel(2, new int[]{2, 2, 2, 2}, forbiddenTupleLists, Collections.emptyList());

        final ConstraintChecker checker = new HardConstraintCheckerFactory().createConstraintChecker(model);
        
        final List<int[]> testSuite = new IpogAlgorithm(IpogConfiguration.ipogConfiguration().testModel(model).checker(checker).build()).generate();
        
        assertFalse(testSuite.stream().anyMatch((int[] test) -> CombinationUtil.contains(test, new int[]{0, -1, 1, -1})));
    }
    
    @Test
    void checkWithUnsatisfiableConstraint() {
        final List<TupleList> forbiddenTupleLists = new ArrayList<>();
        forbiddenTupleLists.add(new TupleList(1, new int[]{2}, Arrays.asList(new int[]{0}, new int[]{1})));
        
        final TestModel model = new TestModel(2, new int[]{2, 2, 2, 2}, forbiddenTupleLists, Collections.emptyList());

        final ConstraintChecker checker = new HardConstraintCheckerFactory().createConstraintChecker(model);
        
        final List<int[]> testSuite = new IpogAlgorithm(IpogConfiguration.ipogConfiguration().testModel(model).checker(checker).build()).generate();
        
        assertEquals(0, testSuite.size());
    }
}
