package de.rwth.swc.coffee4j.model.constraints;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Arrays;
import java.util.List;

import static de.rwth.swc.coffee4j.model.constraints.Constraint.ANONYMOUS_CONSTRAINT;
import static de.rwth.swc.coffee4j.model.constraints.ConstraintStatus.UNKNOWN;

/**
 * Convenience methods for creating constraints on up to six parameters. For all numbers of parameters this works by
 * the same schema. First, a number of parameters is given, then a {@link BooleanFunction1} (with the corresponding
 * number at the end) is required as a constraint function.
 */
public final class ConstraintBuilder {
    
    private ConstraintBuilder() { }

    private static List<String> toNonNullContainingList(String... parameterNames) {
        Preconditions.notNull(parameterNames);

        final List<String> list = Arrays.asList(parameterNames);
        Preconditions.check(!list.contains(null));

        return list;
    }

    /**
     * Starts the build process for a constraint on one parameter.
     *
     * @param firstParameter the name of the first parameter. Must not be {@code null}
     * @return a builder for defining the corresponding {@link ConstraintFunction}
     */
    public static Constraint1Builder constrain(String firstParameter) {
        return constrain(firstParameter, UNKNOWN);
    }

    public static Constraint1Builder constrain(String firstParameter, ConstraintStatus constraintStatus) {
        return new Constraint1Builder(toNonNullContainingList(firstParameter), constraintStatus);
    }

    /**
     * Starts the build process for a constraint on two parameters.
     *
     * @param firstParameter  the name of the first parameter. Must not be {@code null}
     * @param secondParameter the name of the second parameter. Must not be {@code null}
     * @return a builder for defining the corresponding {@link ConstraintFunction}
     */
    public static Constraint2Builder constrain(String firstParameter, String secondParameter) {
        return constrain(firstParameter, secondParameter, UNKNOWN);
    }

    public static Constraint2Builder constrain(String firstParameter, String secondParameter, ConstraintStatus constraintStatus) {
        return new Constraint2Builder(toNonNullContainingList(firstParameter, secondParameter), constraintStatus);
    }

    /**
     * Starts the build process for a constraint on three parameters.
     *
     * @param firstParameter  the name of the first parameter. Must not be {@code null}
     * @param secondParameter the name of the second parameter. Must not be {@code null}
     * @param thirdParameter  the name of the third parameter. Must not be {@code null}
     * @return a builder for defining the corresponding {@link ConstraintFunction}
     */
    public static Constraint3Builder constrain(String firstParameter, String secondParameter, String thirdParameter) {
        return constrain(firstParameter, secondParameter, thirdParameter, UNKNOWN);
    }

    public static Constraint3Builder constrain(String firstParameter, String secondParameter, String thirdParameter, ConstraintStatus constraintStatus) {
        return new Constraint3Builder(toNonNullContainingList(firstParameter, secondParameter, thirdParameter), constraintStatus);
    }

    /**
     * Starts the build process for a constraint on four parameters.
     *
     * @param firstParameter  the name of the first parameter. Must not be {@code null}
     * @param secondParameter the name of the second parameter. Must not be {@code null}
     * @param thirdParameter  the name of the third parameter. Must not be {@code null}
     * @param fourthParameter the name of the fourth parameter. Must not be {@code null}
     * @return a builder for defining the corresponding {@link ConstraintFunction}
     */
    public static Constraint4Builder constrain(String firstParameter, String secondParameter, String thirdParameter, String fourthParameter) {
        return constrain(firstParameter, secondParameter, thirdParameter, fourthParameter, UNKNOWN);
    }

    public static Constraint4Builder constrain(String firstParameter, String secondParameter, String thirdParameter, String fourthParameter, ConstraintStatus constraintStatus) {
        return new Constraint4Builder(toNonNullContainingList(firstParameter, secondParameter, thirdParameter, fourthParameter), constraintStatus);
    }

    /**
     * Starts the build process for a constraint on five parameters.
     *
     * @param firstParameter  the name of the first parameter. Must not be {@code null}
     * @param secondParameter the name of the second parameter. Must not be {@code null}
     * @param thirdParameter  the name of the third parameter. Must not be {@code null}
     * @param fourthParameter the name of the fourth parameter. Must not be {@code null}
     * @param fifthParameter  the name of the fifth parameter. Must not be {@code null}
     * @return a builder for defining the corresponding {@link ConstraintFunction}
     */
    public static Constraint5Builder constrain(String firstParameter, String secondParameter, String thirdParameter, String fourthParameter, String fifthParameter) {
        return constrain(firstParameter, secondParameter, thirdParameter, fourthParameter, fifthParameter, UNKNOWN);
    }

    public static Constraint5Builder constrain(String firstParameter, String secondParameter, String thirdParameter, String fourthParameter, String fifthParameter, ConstraintStatus constraintStatus) {
        return new Constraint5Builder(toNonNullContainingList(firstParameter, secondParameter, thirdParameter, fourthParameter, fifthParameter), constraintStatus);
    }

    /**
     * Starts the build process for a constraint on sic parameters.
     *
     * @param firstParameter  the name of the first parameter. Must not be {@code null}
     * @param secondParameter the name of the second parameter. Must not be {@code null}
     * @param thirdParameter  the name of the third parameter. Must not be {@code null}
     * @param fourthParameter the name of the fourth parameter. Must not be {@code null}
     * @param fifthParameter  the name of the fifth parameter. Must not be {@code null}
     * @param sixthParameter  the name of the sixth parameter. Must not be {@code null}
     * @return a builder for defining the corresponding {@link ConstraintFunction}
     */
    public static Constraint6Builder constrain(String firstParameter, String secondParameter, String thirdParameter, String fourthParameter, String fifthParameter, String sixthParameter) {
        return constrain(firstParameter, secondParameter, thirdParameter, fourthParameter, fifthParameter, sixthParameter, UNKNOWN);
    }

    public static Constraint6Builder constrain(String firstParameter, String secondParameter, String thirdParameter, String fourthParameter, String fifthParameter, String sixthParameter, ConstraintStatus constraintStatus) {
        return new Constraint6Builder(toNonNullContainingList(firstParameter, secondParameter, thirdParameter, fourthParameter, fifthParameter, sixthParameter), constraintStatus);
    }

    /**
     * Builder for giving a constraint on one parameter the corresponding {@link BooleanFunction1}.
     */
    public static final class Constraint1Builder {

        private String name;
        private final List<String> parameterNames;
        private final ConstraintStatus constraintStatus;

        private Constraint1Builder(List<String> parameterNames, ConstraintStatus constraintStatus) {
            this.name = ANONYMOUS_CONSTRAINT;
            this.parameterNames = parameterNames;
            this.constraintStatus = constraintStatus;
        }

        public Constraint1Builder withName(String name) {
            Preconditions.notNull(name);

            this.name = name;

            return this;
        }

        /**
         * Specified the {@link ConstraintFunction} as a {@link BooleanFunction1} for the given parameter.
         *
         * @param constraint the constraint function on the parameter
         * @return a constraint with the given parameter and constraint function
         */
        public Constraint by(BooleanFunction1<?> constraint) {
            Preconditions.notNull(constraint);

            return new Constraint(name, parameterNames, constraint, constraintStatus);
        }
    }
    
    /**
     * Builder for giving a constraint on two parameters the corresponding {@link BooleanFunction2}.
     */
    public static final class Constraint2Builder {

        private String name;
        private final List<String> parameterNames;
        private final ConstraintStatus constraintStatus;

        private Constraint2Builder(List<String> parameterNames, ConstraintStatus constraintStatus) {
            this.name = ANONYMOUS_CONSTRAINT;
            this.parameterNames = parameterNames;
            this.constraintStatus = constraintStatus;
        }

        public Constraint2Builder withName(String name) {
            Preconditions.notNull(name);

            this.name = name;

            return this;
        }

        /**
         * Specified the {@link ConstraintFunction} as a {@link BooleanFunction2} for the given parameters.
         *
         * @param constraint the constraint function on the parameters
         * @return a constraint with the given parameters and constraint function
         */
        public Constraint by(BooleanFunction2<?, ?> constraint) {
            Preconditions.notNull(constraint);

            return new Constraint(name, parameterNames, constraint, constraintStatus);
        }
    }
    
    /**
     * Builder for giving a constraint on three parameters the corresponding {@link BooleanFunction3}.
     */
    public static final class Constraint3Builder {

        private String name;
        private final List<String> parameterNames;
        private final ConstraintStatus constraintStatus;

        private Constraint3Builder(List<String> parameterNames, ConstraintStatus constraintStatus) {
            this.name = ANONYMOUS_CONSTRAINT;
            this.parameterNames = parameterNames;
            this.constraintStatus = constraintStatus;
        }

        public Constraint3Builder withName(String name) {
            Preconditions.notNull(name);

            this.name = name;

            return this;
        }

        /**
         * Specified the {@link ConstraintFunction} as a {@link BooleanFunction3} for the given parameters.
         *
         * @param constraint the constraint function on the parameters
         * @return a constraint with the given parameters and constraint function
         */
        public Constraint by(BooleanFunction3<?, ?, ?> constraint) {
            Preconditions.notNull(constraint);

            return new Constraint(name, parameterNames, constraint, constraintStatus);
        }
    }
    
    /**
     * Builder for giving a constraint on four parameters the corresponding {@link BooleanFunction4}.
     */
    public static final class Constraint4Builder {

        private String name;
        private final List<String> parameterNames;
        private final ConstraintStatus constraintStatus;

        private Constraint4Builder(List<String> parameterNames, ConstraintStatus constraintStatus) {
            this.name = ANONYMOUS_CONSTRAINT;
            this.parameterNames = parameterNames;
            this.constraintStatus = constraintStatus;
        }

        public Constraint4Builder withName(String name) {
            Preconditions.notNull(name);

            this.name = name;

            return this;
        }
        
        /**
         * Specified the {@link ConstraintFunction} as a {@link BooleanFunction4} for the given parameters.
         *
         * @param constraint the constraint function on the parameters
         * @return a constraint with the given parameters and constraint function
         */
        public Constraint by(BooleanFunction4<?, ?, ?, ?> constraint) {
            Preconditions.notNull(constraint);

            return new Constraint(name, parameterNames, constraint, constraintStatus);
        }
    }
    
    /**
     * Builder for giving a constraint on five parameters the corresponding {@link BooleanFunction5}.
     */
    public static final class Constraint5Builder {

        private String name;
        private final List<String> parameterNames;
        private final ConstraintStatus constraintStatus;

        private Constraint5Builder(List<String> parameterNames, ConstraintStatus constraintStatus) {
            this.name = ANONYMOUS_CONSTRAINT;
            this.parameterNames = parameterNames;
            this.constraintStatus = constraintStatus;
        }

        public Constraint5Builder withName(String name) {
            Preconditions.notNull(name);

            this.name = name;

            return this;
        }

        /**
         * Specified the {@link ConstraintFunction} as a {@link BooleanFunction5} for the given parameters.
         *
         * @param constraint the constraint function on the parameters
         * @return a constraint with the given parameters and constraint function
         */
        public Constraint by(BooleanFunction5<?, ?, ?, ?, ?> constraint) {
            Preconditions.notNull(constraint);

            return new Constraint(name, parameterNames, constraint, constraintStatus);
        }
    }
    
    /**
     * Builder for giving a constraint on six parameters the corresponding {@link BooleanFunction6}.
     */
    public static final class Constraint6Builder {

        private String name;
        private final List<String> parameterNames;
        private final ConstraintStatus constraintStatus;

        private Constraint6Builder(List<String> parameterNames, ConstraintStatus constraintStatus) {
            this.name = ANONYMOUS_CONSTRAINT;
            this.parameterNames = parameterNames;
            this.constraintStatus = constraintStatus;
        }

        public Constraint6Builder withName(String name) {
            Preconditions.notNull(name);

            this.name = name;

            return this;
        }

        /**
         * Specified the {@link ConstraintFunction} as a {@link BooleanFunction6} for the given parameters.
         *
         * @param constraint the constraint function on the parameters
         * @return a constraint with the given parameters and constraint function
         */
        public Constraint by(BooleanFunction6<?, ?, ?, ?, ?, ?> constraint) {
            Preconditions.notNull(constraint);

            return new Constraint(name, parameterNames, constraint, constraintStatus);
        }
    }
}
