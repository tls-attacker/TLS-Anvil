package de.rwth.swc.coffee4j.engine.util;

import java.util.OptionalInt;

import static de.rwth.swc.coffee4j.engine.util.ArrayUtil.containsDuplicates;

/**
 * Utilities for tuples that are represented by two separate integer arrays.
 * One array represents the parameters and the other array represents the parameter values.
 */
public final class TupleUtil {

    private TupleUtil() {
    }

    /**
     * Checks if two tuples are equal.
     * For example, parameters={@code [0, 1]}, values={@code [0,1]} and otherParameters={@code [1,0]},
     * otherValues={@code [1,0]} are equal because the value for parameter no. 0 is 0 in both tuples and
     * the value for parameter no. 1 is 1 in both tuples.
     *
     * @param parameters        Parameters of the first tuple
     * @param values            Values of the first tuple
     * @param otherParameters   Parameters of the second tuple
     * @param otherValues       Values of the second tuple
     * @return                  {@code true} if the tuples are equal. Otherwise, {@code false}.
     */
    public static boolean tuplesAreEqual(int[] parameters, int[] values,
                                         int[] otherParameters, int[] otherValues) {
        Preconditions.notNull(parameters);
        Preconditions.check(!containsDuplicates(parameters));
        Preconditions.notNull(values);
        Preconditions.check(parameters.length == values.length);
        Preconditions.notNull(otherParameters);
        Preconditions.check(!containsDuplicates(otherParameters));
        Preconditions.notNull(otherValues);
        Preconditions.check(otherParameters.length == otherValues.length);

        if(parameters.length != otherParameters.length) {
            return false;
        }

        for(int i = 0; i < parameters.length; i++) {
            final int parameter = parameters[i];
            final int value = values[i];

            final OptionalInt indexOfOtherParameter = ArrayUtil.indexOf(otherParameters, parameter);

            if(indexOfOtherParameter.isEmpty()) {
                return false;
            }

            final int otherValue = otherValues[indexOfOtherParameter.getAsInt()];

            if(value != otherValue) {
                return false;
            }
        }

        return true;
    }
}
