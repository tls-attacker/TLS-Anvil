package de.rwth.swc.coffee4j.engine.generator.ipog;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HardConstraintCheckerFactoryTest {
    
    private static final TestModel MODEL = new TestModel(2, new int[]{2, 2, 2, 2}, Collections.emptyList(), Arrays.asList(new TupleList(1, new int[]{0, 1}, Arrays.asList(new int[]{0, 0}, new int[]{1, 1})), new TupleList(2, new int[]{1, 2}, Collections.singletonList(new int[]{1, 1}))));
    
    private static final ConstraintCheckerFactory FACTORY = new HardConstraintCheckerFactory();

    @Test
    void testCreateHardConstraintsChecker() {
        ConstraintChecker checker = FACTORY.createConstraintChecker(MODEL);
        
        assertTrue(checker.isValid(new int[]{0, 1, 0, 0}));
        assertFalse(checker.isValid(new int[]{0, 0, 0, 0}));
    }
    
    @Test
    void testCreateHardConstraintsCheckerWithNegation() {
        TupleList tupleList = new TupleList(1, new int[]{0, 1}, Collections.singletonList(new int[]{0, 0}));
        
        ConstraintChecker checker = FACTORY.createConstraintCheckerWithNegation(MODEL, tupleList);
        
        assertTrue(checker.isValid(new int[]{0, 0, 0, 0}));
        assertFalse(checker.isValid(new int[]{0, 1, 0, 0}));
        assertFalse(checker.isValid(new int[]{0, 1, 1, 0}));
    }
}
