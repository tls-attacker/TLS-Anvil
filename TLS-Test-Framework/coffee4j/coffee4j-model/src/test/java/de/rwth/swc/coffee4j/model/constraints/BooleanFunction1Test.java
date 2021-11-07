package de.rwth.swc.coffee4j.model.constraints;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

class BooleanFunction1Test implements ConstraintFunctionTest {
    
    @Override
    public ConstraintFunction getFunction() {
        return (BooleanFunction1<?>) (String first) -> first.equals("test");
    }
    
    @Override
    public List<?> getTooFewValues() {
        return Collections.emptyList();
    }
    
    @Override
    public List<?> getTooManyValues() {
        return Arrays.asList("one", "two");
    }
    
    @Override
    public List<?> getValuesEvaluatingToTrue() {
        return Collections.singletonList("test");
    }
    
    @Override
    public List<?> getValuesEvaluatingToFalse() {
        return Collections.singletonList("false");
    }
    
    @Override
    public List<?> getValuesOfWrongType() {
        return Collections.singletonList(1);
    }
    
}
