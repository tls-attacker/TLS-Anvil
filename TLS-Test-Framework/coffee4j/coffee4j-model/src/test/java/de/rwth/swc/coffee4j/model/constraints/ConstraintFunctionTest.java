package de.rwth.swc.coffee4j.model.constraints;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

interface ConstraintFunctionTest {
    
    ConstraintFunction getFunction();
    
    List<?> getTooFewValues();
    
    List<?> getTooManyValues();
    
    List<?> getValuesEvaluatingToTrue();
    
    List<?> getValuesEvaluatingToFalse();
    
    List<?> getValuesOfWrongType();
    
    @Test
    default void preconditions() {
        final ConstraintFunction constraintFunction = getFunction();
        
        Assertions.assertThrows(NullPointerException.class, () -> constraintFunction.check(null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> constraintFunction.check(getTooFewValues()));
        Assertions.assertThrows(IllegalArgumentException.class, () -> constraintFunction.check(getTooManyValues()));
    }
    
    @Test
    default void correctlyEvaluatesAndCastsObjects() {
        final ConstraintFunction constraintFunction = getFunction();
        
        assertTrue(constraintFunction.check(getValuesEvaluatingToTrue()));
        assertFalse(constraintFunction.check(getValuesEvaluatingToFalse()));
    }
    
    @Test
    default void throwsExceptionIfValueCannotBeCast() {
        final ConstraintFunction constraintFunction = getFunction();
        
        Assertions.assertThrows(ClassCastException.class, () -> constraintFunction.check(getValuesOfWrongType()));
    }
    
}
