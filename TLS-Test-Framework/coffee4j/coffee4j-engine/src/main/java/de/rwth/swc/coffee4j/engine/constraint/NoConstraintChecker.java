package de.rwth.swc.coffee4j.engine.constraint;

public class NoConstraintChecker implements ConstraintChecker {
    
    @Override
    public boolean isValid(int[] combination) {
        return true;
    }
    
    @Override
    public boolean isExtensionValid(int[] combinations, int... parameterValue) {
        return true;
    }
    
    @Override
    public boolean isDualValid(int[] parameters, int[] values) {
        return true;
    }
}
