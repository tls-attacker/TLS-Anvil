package de.rwth.swc.coffee4j.model.constraints;

import java.util.Arrays;
import java.util.List;

class BooleanFunction6Test implements ConstraintFunctionTest {

    @Override
    public ConstraintFunction getFunction() {
        return (BooleanFunction6<?, ?, ?, ?, ?, ?>) (String first, String second, String third, String fourth, String fifth, String sixth) -> first.equals("test");
    }

    @Override
    public List<?> getTooFewValues() {
        return Arrays.asList("one", "two", "three", "four", "five");
    }

    @Override
    public List<?> getTooManyValues() {
        return Arrays.asList("one", "two", "three", "four", "five", "six", "seven");
    }

    @Override
    public List<?> getValuesEvaluatingToTrue() {
        return Arrays.asList("test", "test", "test", "test", "test", "test");
    }

    @Override
    public List<?> getValuesEvaluatingToFalse() {
        return Arrays.asList("one", "two", "three", "four", "five", "six");
    }

    @Override
    public List<?> getValuesOfWrongType() {
        return Arrays.asList("one", "two", "three", "four", "five", 6);
    }

}
