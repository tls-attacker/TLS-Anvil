package de.rwth.swc.coffee4j.model.constraints;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Collections;
import java.util.List;

/**
 * Defines a constraint for combinatorial testing as a collection of parameters names and a function which can check
 * whether any given value assignment for those parameters is valid or not according to some logic defined by
 * the function.
 */
public class Constraint {

    public static final String ANONYMOUS_CONSTRAINT = "";

    private String name;

    private final List<String> parameterNames;
    
    private final ConstraintFunction constraintFunction;

    private final ConstraintStatus constraintStatus;

    public Constraint(String name, List<String> parameterNames, ConstraintFunction constraintFunction) {
        this(name, parameterNames, constraintFunction, ConstraintStatus.UNKNOWN);
    }

    /**
     * Creates a new constraint. It is most efficient if only the parameters really involved and not additional ones
     * are given.
     * @param name               a name to improve readability without further semantics
     * @param parameterNames     the names of all involved parameters. Must not be, or contain {@code null}, or be empty
     * @param constraintFunction the function by which the values for the parameters are constrained.
     *                           Must not be {@code null}
     * @param constraintStatus   status is either Unknown or Correct which is related to conflict detection
     */
    public Constraint(String name,
                      List<String> parameterNames,
                      ConstraintFunction constraintFunction,
                      ConstraintStatus constraintStatus) {
        Preconditions.notNull(name);
        Preconditions.notNull(parameterNames);
        Preconditions.notNull(constraintFunction);
        Preconditions.notNull(constraintStatus);
        Preconditions.check(!parameterNames.isEmpty());
        Preconditions.check(!parameterNames.contains(null));

        this.name = name;
        this.parameterNames = parameterNames;
        this.constraintFunction = constraintFunction;
        this.constraintStatus = constraintStatus;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    /**
     * @return the names of all involved parameters
     */
    public List<String> getParameterNames() {
        return Collections.unmodifiableList(parameterNames);
    }
    
    /**
     * @return the function constraining the values of the involved parameters
     */
    public ConstraintFunction getConstraintFunction() {
        return constraintFunction;
    }

    public ConstraintStatus getConstraintStatus() {
        return constraintStatus;
    }

    @Override
    public String toString() {
        return "Constraint {name=" + name + ", parameterNames=(" + String.join(", ", parameterNames) + ")}";
    }
}


