package de.rwth.swc.coffee4j.model.constraints;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;

import static de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder.constrain;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ConstraintBuilderTest {
    
    @Test
    void parameterNamesCannotContainNull() {
        assertThrows(IllegalArgumentException.class, () -> constrain(null));
        assertThrows(IllegalArgumentException.class, () -> constrain("first", (String) null));
        assertThrows(IllegalArgumentException.class, () -> constrain("first", "second", (String) null));
        assertThrows(IllegalArgumentException.class, () -> constrain("first", "second", "third", (String) null));
        assertThrows(IllegalArgumentException.class, () -> constrain("first", "second", "third", "fourth", (String) null));
        assertThrows(IllegalArgumentException.class, () -> constrain("first", "second", "third", "fourth", "fifth", (String) null));
    }
    
    @Test
    void constraintByReturnsConstraintWithCorrectParametersAndFunction() {
        final BooleanFunction1<?> firstFunction = Mockito.mock(BooleanFunction1.class);
        final BooleanFunction2<?, ?> secondFunction = Mockito.mock(BooleanFunction2.class);
        final BooleanFunction3<?, ?, ?> thirdFunction = Mockito.mock(BooleanFunction3.class);
        final BooleanFunction4<?, ?, ?, ?> fourthFunction = Mockito.mock(BooleanFunction4.class);
        final BooleanFunction5<?, ?, ?, ?, ?> fifthFunction = Mockito.mock(BooleanFunction5.class);
        final BooleanFunction6<?, ?, ?, ?, ?, ?> sixthFunction = Mockito.mock(BooleanFunction6.class);
        
        final Constraint firstConstraint = constrain("first").by(firstFunction);
        final Constraint secondConstraint = constrain("first", "second").by(secondFunction);
        final Constraint thirdConstraint = constrain("first", "second", "third").by(thirdFunction);
        final Constraint fourthConstraint = constrain("first", "second", "third", "fourth").by(fourthFunction);
        final Constraint fifthConstraint = constrain("first", "second", "third", "fourth", "fifth").by(fifthFunction);
        final Constraint sixthConstraint = constrain("first", "second", "third", "fourth", "fifth", "sixth").by(sixthFunction);
        
        assertEquals(Collections.singletonList("first"), firstConstraint.getParameterNames());
        assertEquals(Arrays.asList("first", "second"), secondConstraint.getParameterNames());
        assertEquals(Arrays.asList("first", "second", "third"), thirdConstraint.getParameterNames());
        assertEquals(Arrays.asList("first", "second", "third", "fourth"), fourthConstraint.getParameterNames());
        assertEquals(Arrays.asList("first", "second", "third", "fourth", "fifth"), fifthConstraint.getParameterNames());
        assertEquals(Arrays.asList("first", "second", "third", "fourth", "fifth", "sixth"), sixthConstraint.getParameterNames());
        
        assertEquals(firstFunction, firstConstraint.getConstraintFunction());
        assertEquals(secondFunction, secondConstraint.getConstraintFunction());
        assertEquals(thirdFunction, thirdConstraint.getConstraintFunction());
        assertEquals(fourthFunction, fourthConstraint.getConstraintFunction());
        assertEquals(fifthFunction, fifthConstraint.getConstraintFunction());
        assertEquals(sixthFunction, sixthConstraint.getConstraintFunction());
    }
    
}
