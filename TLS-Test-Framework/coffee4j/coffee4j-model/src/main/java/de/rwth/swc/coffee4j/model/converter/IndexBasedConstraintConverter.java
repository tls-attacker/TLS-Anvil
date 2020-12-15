package de.rwth.swc.coffee4j.model.converter;

import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.constraints.Constraint;

import java.util.List;

/**
 * Used by {@link IndexBasedModelConverter} to convert a list of {@link Constraint} to a list of {@link TupleList}.
 */
@FunctionalInterface
public interface IndexBasedConstraintConverter {
    
    /**
     * Converts all constraints to tuple lists by using the index based schema explained in {@link ModelConverter}.
     * The constraints need to be converted in order.
     *
     * @param constraints all constraint which need to be converted. Must not be {@code null} but can be empty
     * @param parameters  the parameters containing the values for the conversion. Must not be {@code null}. Can only
     *                    be empty if constraints is empty too as otherwise parameters are constrained
     * @return the converted constraints in the same order as the given constraints
     */
    List<TupleList> convert(List<Constraint> constraints, List<Parameter> parameters);
}
