package de.rwth.swc.coffee4j.model.constraints;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

class BooleanFunction2Test implements ConstraintFunctionTest {

    @Override
    public ConstraintFunction getFunction() {
        return (BooleanFunction2<?, ?>) (String first, String second) -> first.equals("test");
    }

    @Override
    public List<?> getTooFewValues() {
        return Collections.singletonList("test");
    }

    @Override
    public List<?> getTooManyValues() {
        return Arrays.asList("one", "two", "three");
    }

    @Override
    public List<?> getValuesEvaluatingToTrue() {
        return Arrays.asList("test", "test");
    }

    @Override
    public List<?> getValuesEvaluatingToFalse() {
        return Arrays.asList("one", "two");
    }

    @Override
    public List<?> getValuesOfWrongType() {
        return Arrays.asList("test", 2);
    }

}
