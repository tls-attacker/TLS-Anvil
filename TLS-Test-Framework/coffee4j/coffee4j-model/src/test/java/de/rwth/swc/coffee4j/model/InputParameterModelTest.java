package de.rwth.swc.coffee4j.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InputParameterModelTest {
    
    @ParameterizedTest
    @MethodSource("preconditionViolations")
    void violatesPreconditions(Supplier<InputParameterModel> modelSupplier) {
        Assertions.assertThrows(IllegalArgumentException.class, modelSupplier::get);
    }
    
    private static Stream<Arguments> preconditionViolations() {
        return Stream.of(modelSupplierArgument(() -> new InputParameterModel(1, "", Collections.emptyList())), modelSupplierArgument(() -> new InputParameterModel(2, "", Collections.singletonList(Parameter.parameter("test").values(1, 2).build()))), modelSupplierArgument(() -> new InputParameterModel(-1, "", Collections.singletonList(Parameter.parameter("test").values(1, 2).build()))), modelSupplierArgument(() -> new InputParameterModel(1, "", Collections.singletonList(null))));
    }
    
    private static Arguments modelSupplierArgument(Supplier<InputParameterModel> supplier) {
        return Arguments.of(supplier);
    }
    
    @Test
    void builder() {
        final InputParameterModel model = InputParameterModel.inputParameterModel("name").strength(1).parameters(Parameter.parameter("param1").values(1, 2, 3), Parameter.parameter("param2").values(4, 5, 6)).parameter(Parameter.parameter("param3").values(7, 8, 9).build()).build();
        
        assertEquals("name", model.getName());
        assertEquals(1, model.getStrength());
        assertEquals(3, model.size());
        assertEquals(1, model.getParameters().get(0).getValues().get(0).get());
        assertEquals(2, model.getParameters().get(0).getValues().get(1).get());
        assertEquals(3, model.getParameters().get(0).getValues().get(2).get());
        assertEquals(4, model.getParameters().get(1).getValues().get(0).get());
        assertEquals(5, model.getParameters().get(1).getValues().get(1).get());
        assertEquals(6, model.getParameters().get(1).getValues().get(2).get());
        assertEquals(7, model.getParameters().get(2).getValues().get(0).get());
        assertEquals(8, model.getParameters().get(2).getValues().get(1).get());
        assertEquals(9, model.getParameters().get(2).getValues().get(2).get());
    }
    
    @Test
    void sameParameterNameCannotAppearTwice() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> InputParameterModel.inputParameterModel("test").strength(2).parameters(Parameter.parameter("param1").values(0, 1), Parameter.parameter("param1").values(0, 1)).build());
    }
    
}
