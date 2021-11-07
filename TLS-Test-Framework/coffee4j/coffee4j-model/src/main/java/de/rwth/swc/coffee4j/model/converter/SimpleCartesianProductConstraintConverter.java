package de.rwth.swc.coffee4j.model.converter;

import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.util.Combinator;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import de.rwth.swc.coffee4j.model.constraints.ConstraintFunction;
import de.rwth.swc.coffee4j.model.constraints.ConstraintStatus;
import it.unimi.dsi.fastutil.ints.Int2IntMap;
import it.unimi.dsi.fastutil.ints.Int2IntOpenHashMap;
import it.unimi.dsi.fastutil.ints.Int2ObjectMap;
import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;
import it.unimi.dsi.fastutil.objects.Object2IntMap;
import it.unimi.dsi.fastutil.objects.Object2IntOpenHashMap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Converts {@link Constraint} objects to their {@link TupleList} representation by executing their
 * {@link ConstraintFunction} with every possible value combination of its
 * parameters. This means the cartesian product of its parameters values is used.
 * For example, if a constraint uses parameters "param1" with value "1" and "2" and "param2" with value "5" and "6",
 * then the constraint it tested with all these combinations: {"1", "5"}, {"1", "6"}, {"2", "5"} ,{"2", "6"}.
 * For all combinations for which the {@link ConstraintFunction}
 * returns {@code false}, a corresponding tuple is added to the {@link TupleList} representation.
 * Naturally, this is a very expensive conversion process, especially if there are many large parameters involved.
 */
public class SimpleCartesianProductConstraintConverter implements IndexBasedConstraintConverter {
    
    @Override
    public List<TupleList> convert(List<Constraint> constraints, List<Parameter> parameters) {
        Preconditions.notNull(constraints);
        Preconditions.notNull(parameters);
        final Int2ObjectMap<Parameter> idToParameterMap = constructIdToParameterMap(parameters);
        final Object2IntMap<String> parameterNameIdMap = constructParameterNameMap(parameters);
        
        assertContainsOnlyValidParameters(constraints, parameterNameIdMap.keySet());
        
        final List<TupleList> convertedConstraints = new ArrayList<>();
        
        for (int i = 0; i < constraints.size(); i++) {
            convertedConstraints.add(convertedConstraint(constraints.get(i), parameterNameIdMap, idToParameterMap, i + 1));
        }
        
        return convertedConstraints;
    }
    
    private Int2ObjectMap<Parameter> constructIdToParameterMap(List<Parameter> parameters) {
        final Int2ObjectMap<Parameter> idToParameterMap = new Int2ObjectOpenHashMap<>();
        
        for (int i = 0; i < parameters.size(); i++) {
            idToParameterMap.put(i, parameters.get(i));
        }
        
        return idToParameterMap;
    }
    
    private Object2IntMap<String> constructParameterNameMap(List<Parameter> parameters) {
        final Object2IntMap<String> parameterNameMap = new Object2IntOpenHashMap<>();
        
        for (int i = 0; i < parameters.size(); i++) {
            parameterNameMap.put(parameters.get(i).getName(), i);
        }
        
        return parameterNameMap;
    }
    
    private void assertContainsOnlyValidParameters(List<Constraint> constraints, Collection<String> parameterNames) {
        for (Constraint constraint : constraints) {
            Preconditions.check(parameterNames.containsAll(constraint.getParameterNames()));
        }
    }
    
    private TupleList convertedConstraint(Constraint constraint, Object2IntMap<String> parameterIdMap, Int2ObjectMap<Parameter> idToParameterMap, int id) {
        int[] relevantParameters = constraint.getParameterNames().stream().mapToInt(parameterIdMap::getInt).toArray();
        final Int2IntMap relevantParameterSizes = computeSizeMap(idToParameterMap, relevantParameters);
        
        final Collection<int[]> cartesianProduct = Combinator.computeCartesianProduct(relevantParameterSizes, relevantParameters.length);
        final List<int[]> tuples = new ArrayList<>();
        
        for (int[] combination : cartesianProduct) {
            final List<?> arguments = mapToArguments(combination, relevantParameters, idToParameterMap);
            if (!constraint.getConstraintFunction().check(arguments)) {
                int[] tuple = new int[combination.length];
                System.arraycopy(combination, 0, tuple, 0, combination.length);
                tuples.add(tuple);
            }
        }
        
        return new TupleList(id, relevantParameters, tuples, constraint.getConstraintStatus().equals(ConstraintStatus.CORRECT));
    }
    
    private Int2IntMap computeSizeMap(Int2ObjectMap<Parameter> idToParameterMap, int[] relevantKeys) {
        final Int2IntMap subMap = new Int2IntOpenHashMap();
        
        for (int i = 0; i < relevantKeys.length; i++) {
            final Parameter relevantParameter = idToParameterMap.get(relevantKeys[i]);
            subMap.put(i, relevantParameter.size());
        }
        
        return subMap;
    }
    
    private List<Object> mapToArguments(int[] combination, int[] relevantParameters, Int2ObjectMap<Parameter> idToParameterMap) {
        final List<Object> arguments = new ArrayList<>(relevantParameters.length);
        
        for (int i = 0; i < relevantParameters.length; i++) {
            final int valueId = combination[i];
            arguments.add(idToParameterMap.get(relevantParameters[i]).getValues().get(valueId).get());
        }
        
        return arguments;
    }
}
