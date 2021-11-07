package de.rwth.swc.coffee4j.model.constraints;

import java.util.Arrays;
import java.util.List;

class BooleanFunction5Test implements ConstraintFunctionTest {

    @Override
    public ConstraintFunction getFunction() {
        return (BooleanFunction5<?, ?, ?, ?, ?>) (String first, String second, String third, String fourth, String fifth) -> first.equals("test");
    }

    @Override
    public List<?> getTooFewValues() {
        return Arrays.asList("one", "two", "three", "four");
    }

    @Override
    public List<?> getTooManyValues() {
        return Arrays.asList("one", "two", "three", "four", "five", "six");
    }

    @Override
    public List<?> getValuesEvaluatingToTrue() {
        return Arrays.asList("test", "test", "test", "test", "test");
    }

    @Override
    public List<?> getValuesEvaluatingToFalse() {
        return Arrays.asList("one", "two", "three", "four", "five");
    }

    @Override
    public List<?> getValuesOfWrongType() {
        return Arrays.asList("one", "two", "three", "four", 5);
    }

}
