package de.rwth.swc.coffee4j.engine.constraint;

public interface ConstraintChecker {

    boolean isValid(int[] combination);

    boolean isExtensionValid(int[] combination, int... parameterValues);
    
    boolean isDualValid(int[] parameters, int[] values);
}
