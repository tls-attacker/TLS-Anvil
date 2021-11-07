package de.rwth.swc.coffee4j.model;

import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.constraints.Constraint;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static de.rwth.swc.coffee4j.model.constraints.Constraint.ANONYMOUS_CONSTRAINT;

/**
 * An representation of a input parameter testModel for combinatorial testing. Consists of a testing strength,
 * readable name for identification, parameter, and forbidden and error constraints.
 * This testModel defines all important aspects of one combinatorial test.
 */
public final class InputParameterModel {
    
    private final int strength;
    
    private final String name;
    
    private final List<Parameter> parameters;
    
    private final List<Constraint> exclusionConstraints;
    private final List<Constraint> errorConstraints;
    
    /**
     * Creates a new testModel with no constraints.
     *
     * @param strength   the testing strength. Must be equal to or greater than one and at most the number of parameters
     * @param name       the name of the testModel. Should be human readable. Must not be {@code null}
     * @param parameters all parameters of the testModel. Must not be, nor contain {@code null} and must not be empty.
     *                   Must not contain parameters with duplicate names
     */
    public InputParameterModel(int strength, String name, List<Parameter> parameters) {
        this(strength, name, parameters, Collections.emptyList(), Collections.emptyList());
    }
    
    /**
     * Creates a new testModel with all given configuration arguments.
     *
     * @param strength             the testing strength. Must be equal to or greater than one and at most the number of parameters
     * @param name                 the name of the testModel. Should be human readable. Must not be {@code null}
     * @param parameters           all parameters of the testModel. Must not be, nor contain {@code null} and must not be empty.
     * @param exclusionConstraints all constraints which may never be violated as test inputs won't work then
     *                             May not be, nor contain {@code null}
     * @param errorConstraints     all constraints which may be violated but will cause the system to throw an exception.
     *                             *                  All in all describes input which should not be allowed.
     *                             May not be, nor contain {@code null}
     */
    public InputParameterModel(int strength, String name, List<Parameter> parameters, Collection<Constraint> exclusionConstraints, Collection<Constraint> errorConstraints) {
        Preconditions.notNull(name);
        Preconditions.notNull(parameters);
        Preconditions.notNull(exclusionConstraints);
        Preconditions.notNull(errorConstraints);
        Preconditions.check(strength >= 0);
        Preconditions.check(strength <= parameters.size());
        Preconditions.check(!parameters.contains(null));
        Preconditions.check(!exclusionConstraints.contains(null));
        Preconditions.check(!errorConstraints.contains(null));
        checkParameterDoesNotContainDuplicateName(parameters);

        countAnonymousConstraints(exclusionConstraints, errorConstraints);

        this.strength = strength;
        this.name = name;
        this.parameters = new ArrayList<>(parameters);
        this.exclusionConstraints = new ArrayList<>(exclusionConstraints);
        this.errorConstraints = new ArrayList<>(errorConstraints);
    }

    private void countAnonymousConstraints(Collection<Constraint> exclusionConstraints,
                                           Collection<Constraint> errorConstraints) {
        int count = 0;

        for(Constraint constraint : exclusionConstraints) {
            if(constraint.getName().equals(ANONYMOUS_CONSTRAINT)) {
                constraint.setName("unknown-" + ++count);
            }
        }

        for(Constraint constraint : errorConstraints) {
            if(constraint.getName().equals(ANONYMOUS_CONSTRAINT)) {
                constraint.setName("unknown-" + ++count);
            }
        }
    }

    private static void checkParameterDoesNotContainDuplicateName(List<Parameter> parameters) {
        final Set<String> parameterNames = new HashSet<>();
        
        for (Parameter parameter : parameters) {
            final String parameterName = parameter.getName();
            if (parameterNames.contains(parameterName)) {
                throw new IllegalArgumentException("Parameter name " + parameterName + " appears twice");
            }
            parameterNames.add(parameterName);
        }
    }
    
    /**
     * @return the testing strength
     */
    public int getStrength() {
        return strength;
    }
    
    /**
     * @return the descriptive name of the testModel
     */
    public String getName() {
        return name;
    }
    
    /**
     * @return a copy of the list of all parameters of this testModel
     */
    public List<Parameter> getParameters() {
        return Collections.unmodifiableList(parameters);
    }
    
    /**
     * @return a copy of the list of all forbidden constraints. Test inputs may never violate those constraints as they
     * define combinations which are not possible testable (like testing safari on windows is not possible)
     */
    public List<Constraint> getExclusionConstraints() {
        return Collections.unmodifiableList(exclusionConstraints);
    }
    
    /**
     * @return a copy of the list of all error constraints. Test inputs may violate these constraints but they define
     * inputs on which the system under test should react in a destructive way like raising exception
     * (like trying to parse "asfd" as a number)
     */
    public List<Constraint> getErrorConstraints() {
        return Collections.unmodifiableList(errorConstraints);
    }
    
    /**
     * @return the number of parameters
     */
    public int size() {
        return parameters.size();
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        
        final InputParameterModel model = (InputParameterModel) o;
        return strength == model.strength && Objects.equals(name, model.name) && Objects.equals(parameters, model.parameters) && Objects.equals(exclusionConstraints, model.exclusionConstraints) && Objects.equals(errorConstraints, model.errorConstraints);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(strength, name, parameters, exclusionConstraints, errorConstraints);
    }
    
    @Override
    public String toString() {
        return "InputParameterModel{" + "strength=" + strength + ", name='" + name + '\'' + ", parameters=" + parameters + ", exclusionConstraints=" + exclusionConstraints + ", errorConstraints=" + errorConstraints + '}';
    }
    
    public static Builder inputParameterModel(String name) {
        return new Builder(name);
    }
    
    /**
     * Realization of the builder pattern for constructing a {@link InputParameterModel}. Entry point is
     * {@link #inputParameterModel(String)}.
     */
    public static final class Builder {
        
        private int strength = 1;
        
        private String name;
        
        private final List<Parameter> parameters = new ArrayList<>();
        
        private final List<Constraint> exclusionConstraints = new ArrayList<>();
        private final List<Constraint> errorConstraints = new ArrayList<>();
        
        private Builder(String name) {
            this.name = name;
        }
        
        /**
         * Stets the testing strength. Default is one.
         *
         * @param strength the testing strength
         * @return this
         */
        public Builder strength(int strength) {
            this.strength = strength;
            
            return this;
        }
        
        /**
         * Sets the name. This may not be {@code null} when {@link #build()} is called.
         *
         * @param name a descriptive name for the testModel
         * @return this
         */
        public Builder name(String name) {
            this.name = name;
            
            return this;
        }
        
        /**
         * Adds a parameter to the testModel.
         *
         * @param parameter the parameter. Must not be {@code null}
         * @return this
         */
        public Builder parameter(Parameter parameter) {
            Preconditions.notNull(parameter);
            
            parameters.add(parameter);
            
            return this;
        }
        
        /**
         * Adds the parameter builders to the testModel by building them. This is a convenience method as now the user
         * does not have to call {@link Parameter.Builder#build()} himself, therefore creating more readable code.
         *
         * @param parameter the parameter to be build. Must not be {@code null}
         * @return this
         */
        public Builder parameter(Parameter.Builder parameter) {
            Preconditions.notNull(parameter);
            
            parameters.add(parameter.build());
            
            return this;
        }
        
        /**
         * Adds all parameters to the testModel.
         *
         * @param parameters all parameters to be added. Must not be, nor contain {@code null}
         * @return this
         */
        public Builder parameters(Parameter... parameters) {
            Preconditions.notNull(parameters);
            
            for (Parameter parameter : parameters) {
                parameter(parameter);
            }
            
            return this;
        }
        
        /**
         * Builds all given builders and adds the result parameters to the testModel.
         *
         * @param parameters the parameters to be added. Must not be, nor contain {@code null}
         * @return this
         */
        public Builder parameters(Parameter.Builder... parameters) {
            Preconditions.notNull(parameters);
            
            for (Parameter.Builder parameter : parameters) {
                parameter(parameter);
            }
            
            return this;
        }
        
        /**
         * Adds a forbidden constraint to the testModel.
         *
         * @param exclusionConstraint the forbidden constraint to be added. Must not be {@code null}
         * @return this
         */
        public Builder exclusionConstraint(Constraint exclusionConstraint) {
            Preconditions.notNull(exclusionConstraint);
            
            exclusionConstraints.add(exclusionConstraint);
            
            return this;
        }
        
        /**
         * Adds all forbidden constraints to the testModel.
         *
         * @param exclusionConstraints the forbidden constraints to be added. Must not be, nor contain {@code null}
         * @return this
         */
        public Builder exclusionConstraints(Constraint... exclusionConstraints) {
            Preconditions.notNull(exclusionConstraints);
            
            for (Constraint constraint : exclusionConstraints) {
                exclusionConstraint(constraint);
            }
            
            return this;
        }
        
        /**
         * Adds a error constraint to the testModel.
         *
         * @param errorConstraint the error constraint to be added. Must not be {@code null}
         * @return this
         */
        public Builder errorConstraint(Constraint errorConstraint) {
            Preconditions.notNull(errorConstraint);
            
            errorConstraints.add(errorConstraint);
            
            return this;
        }
        
        /**
         * Adds all error constraints to the testModel.
         *
         * @param errorConstraints the error constraints to be added. Must not be, nor contain {@code null}
         * @return this
         */
        public Builder errorConstraints(Constraint... errorConstraints) {
            Preconditions.notNull(errorConstraints);
            
            for (Constraint constraint : errorConstraints) {
                errorConstraint(constraint);
            }
            
            return this;
        }
        
        /**
         * Builds the testModel. Add least one parameter needs to have been added by now.
         *
         * @return the constructed testModel
         */
        public InputParameterModel build() {
            return new InputParameterModel(strength, name, parameters, exclusionConstraints, errorConstraints);
        }
    }
}
