package de.rwth.swc.coffee4j.model.converter;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.Value;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.NO_VALUE;
import static de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder.constrain;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IndexBasedModelConverterTest {
    
    @ParameterizedTest
    @MethodSource
    void parameterModelAndConstraintsConversion(InputParameterModel.Builder modelBuilder) {
        final InputParameterModel model = modelBuilder.build();
        final IndexBasedModelConverter converter = new IndexBasedModelConverter(model);
        
        assertEquals(model, converter.getModel());
        verifyAllParameterConversions(model, converter);
        verifyAllConstraintsConvertedCorrectly(model, converter);
        verifyCombinatorialTestModel(model, converter.getConvertedModel());
    }
    
    private static Stream<Arguments> parameterModelAndConstraintsConversion() {
        return Stream.of(Arguments.arguments(InputParameterModel.inputParameterModel("name").strength(1).parameters(Parameter.parameter("param").values(0, 1))), Arguments.arguments(InputParameterModel.inputParameterModel("name").strength(2).parameters(Parameter.parameter("param1").values(0, 1), Parameter.parameter("param2").values("one", "two", "three"), Parameter.parameter("param3").values(1.1, 2.2, 3.3, 4.4))), Arguments.arguments(InputParameterModel.inputParameterModel("name").strength(1).parameter(Parameter.parameter("param").values(0, 1, 2)).errorConstraint(constrain("param").by((Integer param) -> param != 1)).exclusionConstraint(constrain("param").by((Integer param) -> param != 0))), Arguments.arguments(InputParameterModel.inputParameterModel("name").strength(1).parameters(Parameter.parameter("param1").values(0, 1), Parameter.parameter("param2").values(0, 1, 2), Parameter.parameter("param3").values(0, 2, 3)).errorConstraint(constrain("param2", "param3").by((Integer param2, Integer param3) -> !param2.equals(param3))).exclusionConstraint(constrain("param1", "param3").by((Integer param1, Integer param2) -> !param1.equals(param2)))));
    }
    
    private void verifyAllParameterConversions(InputParameterModel model, ModelConverter converter) {
        for (int parameterId = 0; parameterId < model.size(); parameterId++) {
            final Parameter parameter = model.getParameters().get(parameterId);
            assertEquals(parameterId, converter.convertParameter(parameter));
            assertEquals(parameter, converter.convertParameter(parameterId));
            
            for (int valueId = 0; valueId < parameter.size(); valueId++) {
                final Value value = parameter.getValues().get(valueId);
                assertEquals(valueId, converter.convertValue(parameter, value));
                assertEquals(value, converter.convertValue(parameterId, valueId));
            }
        }
    }
    
    private void verifyAllConstraintsConvertedCorrectly(InputParameterModel model, ModelConverter converter) {
        final List<Constraint> allConstraints = new ArrayList<>(model.getExclusionConstraints());
        allConstraints.addAll(model.getErrorConstraints());
        
        for (Constraint constraint : allConstraints) {
            final TupleList convertedConstraint = converter.convertConstraint(constraint);
            assertEquals(constraint, converter.convertConstraint(convertedConstraint));
            assertEquals(constraint.getParameterNames().size(), convertedConstraint.getInvolvedParameters().length);
            
            for (int i = 0; i < convertedConstraint.getInvolvedParameters().length; i++) {
                final Parameter involvedParameter = converter.convertParameter(convertedConstraint.getInvolvedParameters()[i]);
                assertTrue(constraint.getParameterNames().contains(involvedParameter.getName()));
            }
        }
    }
    
    private void verifyCombinatorialTestModel(InputParameterModel model, TestModel convertedModel) {
        assertEquals(model.getStrength(), convertedModel.getStrength());
        assertEquals(model.size(), convertedModel.getNumberOfParameters());
        assertEquals(model.size(), convertedModel.getParameterSizes().length);
        
        for (int parameterId = 0; parameterId < model.size(); parameterId++) {
            final Parameter parameter = model.getParameters().get(parameterId);
            assertEquals(parameter.size(), convertedModel.getSizeOfParameter(parameterId));
            assertEquals(parameter.size(), convertedModel.getParameterSizes()[parameterId]);
        }
    }
    
    @Test
    void combinationConversion() {
        final InputParameterModel model = InputParameterModel.inputParameterModel("name").strength(2).parameters(Parameter.parameter("param1").values(0, 1), Parameter.parameter("param2").values("one", "two", "three"), Parameter.parameter("param3").values(1.1, 2.2, 3.3, 4.4)).build();
        final ModelConverter converter = new IndexBasedModelConverter(model);
        
        int[] combination = new int[]{NO_VALUE, NO_VALUE, NO_VALUE};
        Combination convertedCombination = converter.convertCombination(combination);
        assertEquals(0, convertedCombination.size());
        assertEquals(Collections.emptyMap(), convertedCombination.getParameterValueMap());
        assertArrayEquals(combination, converter.convertCombination(convertedCombination));
        
        combination = new int[]{NO_VALUE, 1, NO_VALUE};
        convertedCombination = converter.convertCombination(combination);
        assertEquals(1, convertedCombination.size());
        Assertions.assertEquals(Value.value(1, "two"), convertedCombination.getValue(model.getParameters().get(1)));
        assertArrayEquals(combination, converter.convertCombination(convertedCombination));
    }
    
}
