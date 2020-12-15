package de.rwth.swc.coffee4j.model.constraints;

import java.util.Arrays;
import java.util.List;

class BooleanFunction4Test implements ConstraintFunctionTest {
    
    @Override
    public ConstraintFunction getFunction() {
        return (BooleanFunction4<?, ?, ?, ?>) (String first, String second, String third, String fourth) -> first.equals("test");
    }
    
    @Override
    public List<?> getTooFewValues() {
        return Arrays.asList("one", "two", "three");
    }
    
    @Override
    public List<?> getTooManyValues() {
        return Arrays.asList("one", "two", "three", "four", "five");
    }
    
    @Override
    public List<?> getValuesEvaluatingToTrue() {
        return Arrays.asList("test", "test", "test", "test");
    }
    
    @Override
    public List<?> getValuesEvaluatingToFalse() {
        return Arrays.asList("one", "two", "three", "four");
    }
    
    @Override
    public List<?> getValuesOfWrongType() {
        return Arrays.asList("one", "two", "three", 4);
    }
    
}
