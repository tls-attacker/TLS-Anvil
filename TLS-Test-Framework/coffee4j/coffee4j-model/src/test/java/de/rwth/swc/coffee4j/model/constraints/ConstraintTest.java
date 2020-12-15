package de.rwth.swc.coffee4j.model.constraints;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ConstraintTest {

    @Test
    void preconditions() {
        Assertions.assertThrows(NullPointerException.class, () -> new Constraint("", null, Mockito.mock(ConstraintFunction.class)));
        Assertions.assertThrows(NullPointerException.class, () -> new Constraint("", Collections.emptyList(), null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Constraint("", Collections.singletonList(null), Mockito.mock(ConstraintFunction.class)));
    }

    @Test
    void canCreateConstraint() {
        final List<String> parameterNames = Arrays.asList("first", "second");
        final ConstraintFunction function = list -> true;

        final Constraint constraint = new Constraint("", parameterNames, function);

        assertEquals(parameterNames, constraint.getParameterNames());
        assertEquals(function, constraint.getConstraintFunction());
    }

}
