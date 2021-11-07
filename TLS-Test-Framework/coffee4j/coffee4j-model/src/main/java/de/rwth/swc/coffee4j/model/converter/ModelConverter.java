package de.rwth.swc.coffee4j.model.converter;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.Value;
import de.rwth.swc.coffee4j.model.constraints.Constraint;

/**
 * An interface for classes which can convert an {@link InputParameterModel} to a {@link TestModel}.
 * Additionally, all sub-resources like parameters, combinations, and constraints can be converted.
 */
public interface ModelConverter {
    
    /**
     * @return the original testModel which is converted by this {@link ModelConverter}
     */
    InputParameterModel getModel();
    
    /**
     * @return the conversion of the original testModel ({@link #getModel()})
     */
    TestModel getConvertedModel();
    
    /**
     * Converts a {@link Combination} object to an integer array representation with the corresponding value number.
     * If the array returned by this method is given into {@link #convertCombination(int[])}, a {@link Combination}
     * equal to the original one should be returned.
     *
     * @param combination the combination to be converted. Must not be {@code null}
     * @return the corresponding integer array to that it matches the testModel conversion
     */
    int[] convertCombination(Combination combination);
    
    /**
     * Converts a combinations represented by an integer array into a {@link Combination} object with the corresponding
     * parameters and values.
     *
     * @param combination the combination to be converted. Must not be {@code null}
     * @return the corresponding {@link Combination} so that it matches the testModel conversion
     */
    Combination convertCombination(int[] combination);
    
    /**
     * Converts a {@link Constraint} object into a {@link TupleList} representation which is equal. If the
     * {@link TupleList} returned by this method is given to {@link #convertConstraint(TupleList)}, the original
     * constraint will be returned.
     *
     * @param constraint the constraint to convert. Needs to be one in the original testModel, otherwise success of this
     *                   method is not guaranteed. Must not be {@code null}
     * @return the corresponding {@link TupleList} representation so that it matches the testModel conversion
     */
    TupleList convertConstraint(Constraint constraint);
    
    /**
     * Converts a {@link TupleList} object into a {@link Constraint} representation which is equal.
     *
     * @param constraint the constraint to convert. Needs to be one in the original testModel, otherwise success of this
     *                   method is not guaranteed. Must not be {@code null}
     * @return the corresponding {@link Constraint} representation so that it matches the testModel conversion
     */
    Constraint convertConstraint(TupleList constraint);
    
    /**
     * Converts a {@link Parameter} object into an equivalent integer representation. If the integer returned by
     * this method is given to {@link #convertParameter(int)}, the original parameter is returned.
     *
     * @param parameter the parameter to convert. Needs to be in the original testModel, otherwise success of this method
     *                  is not guaranteed. Must not be {@code null}
     * @return the corresponding integer representation so that it matches the testModel conversion
     */
    int convertParameter(Parameter parameter);
    
    /**
     * Converts an integer representation back to a {@link Parameter} object.
     *
     * @param parameter the parameter to convert. Needs to be in the original testModel, otherwise success of this method
     *                  is not guaranteed. Must not be negative
     * @return the corresponding {@link Parameter} representation so that it matches the testModel conversion
     */
    Parameter convertParameter(int parameter);
    
    /**
     * Converts a {@link Value} to an integer representation. As values are only unique in their corresponding
     * {@link Parameter}s, the parameter is needed as well. It can be converted using
     * {@link #convertParameter(Parameter)}. If the converted value and parameter are given to
     * {@link #convertValue(int, int)}, the original value is returned.
     *
     * @param parameter the parameter in which the value is located
     * @param value     the value to convert
     * @return the corresponding integer representation so that it matches the testModel conversion
     */
    int convertValue(Parameter parameter, Value value);
    
    /**
     * Converts the integer representation of a value into a {@link Value} object. The parameter is needed since
     * values are only unique in the context of their parameters. The parameter can be converted with
     * {@link #convertParameter(int)}.
     *
     * @param parameter the parameter in which the value is located
     * @param value     the value to convert
     * @return the corresponding {@link Value} representation so that it matches the testModel conversion
     */
    Value convertValue(int parameter, int value);
    
}
