package de.rwth.swc.coffee4j.model.converter;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.Value;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import it.unimi.dsi.fastutil.objects.Object2IntMap;
import it.unimi.dsi.fastutil.objects.Object2IntOpenHashMap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * A {@link ModelConverter} based on using the indices of supplied {@link Parameter} and {@link Value}. This means
 * that the first parameter in the list of {@link InputParameterModel#getParameters()} is translated to 0, the second
 * one to 1 and so on and so fourth. The same is done with values per parameter.
 * These integers are then used for {@link TupleList} and {@link Combination}, so [0, 1] is a combination
 * where the first parameter is mapped to it's first value and the second one to its second value.
 */
public class IndexBasedModelConverter implements ModelConverter {
    
    private final InputParameterModel model;
    
    private final Object2IntMap<Parameter> parameterToIdMap = new Object2IntOpenHashMap<>();
    private final Map<Parameter, Object2IntMap<Value>> parameterValueToIdMap = new HashMap<>();
    private final Map<Constraint, TupleList> constraintToTuplesListMap = new HashMap<>();
    private final Map<TupleList, Constraint> tuplesListToConstraintMap = new HashMap<>();
    
    private final TestModel convertedModel;
    
    /**
     * Creates and initializes a new converter with a {@link SimpleCartesianProductConstraintConverter} to convert
     * {@link Constraint} to {@link TupleList}.
     *
     * @param model the testModel which is converted. Must not be {@code null}
     */
    public IndexBasedModelConverter(InputParameterModel model) {
        this(model, new SimpleCartesianProductConstraintConverter());
    }
    
    /**
     * Creates and initializes a new converter with the given testModel and constraints converter.
     *
     * @param model                the testModel which is converted. Must not be {@code null}
     * @param constraintsConverter the converter used to convert the testModel's {@link Constraint} to {@link TupleList}
     */
    public IndexBasedModelConverter(InputParameterModel model,
                                    IndexBasedConstraintConverter constraintsConverter) {
        this.model = Preconditions.notNull(model);
        
        initializeConversionMaps();
        convertTuplesLists(constraintsConverter);
        
        convertedModel = createConvertedModel();
    }
    
    private void initializeConversionMaps() {
        for (int parameterId = 0; parameterId < model.size(); parameterId++) {
            final Parameter correspondingParameter = model.getParameters().get(parameterId);
            final Object2IntMap<Value> valueToIdMap = parameterValueToIdMap.computeIfAbsent(correspondingParameter, parameter -> new Object2IntOpenHashMap<>());
            
            parameterToIdMap.put(correspondingParameter, parameterId);
            for (int valueId = 0; valueId < correspondingParameter.size(); valueId++) {
                valueToIdMap.put(correspondingParameter.getValues().get(valueId), valueId);
            }
        }
    }
    
    private void convertTuplesLists(IndexBasedConstraintConverter constraintsConverter) {
        final List<Constraint> allConstraints = new ArrayList<>(model.getExclusionConstraints());
        allConstraints.addAll(model.getErrorConstraints());
        
        final List<TupleList> correspondingTupleLists = constraintsConverter
                .convert(allConstraints, model.getParameters());
        
        for (int i = 0; i < allConstraints.size(); i++) {
            final Constraint constraint = allConstraints.get(i);
            final TupleList tupleList = correspondingTupleLists.get(i);
            
            constraintToTuplesListMap.put(constraint, tupleList);
            tuplesListToConstraintMap.put(tupleList, constraint);
        }
    }
    
    private TestModel createConvertedModel() {
        int[] parameterSizes = IntStream.range(0, model.size())
                .map(parameterId -> model.getParameters().get(parameterId).size())
                .toArray();
        
        return new TestModel(
                model.getStrength(),
                parameterSizes,
                model.getExclusionConstraints().stream()
                        .map(constraintToTuplesListMap::get)
                        .collect(Collectors.toList()),
                model.getErrorConstraints().stream()
                        .map(constraintToTuplesListMap::get)
                        .collect(Collectors.toList()));
    }
    
    @Override
    public InputParameterModel getModel() {
        return model;
    }
    
    @Override
    public TestModel getConvertedModel() {
        return convertedModel;
    }
    
    @Override
    public int[] convertCombination(Combination combination) {
        Preconditions.notNull(combination);
        
        int[] combinationArray = CombinationUtil.emptyCombination(model.size());
        
        for (Map.Entry<Parameter, Value> mapping : combination.getParameterValueMap().entrySet()) {
            final int parameterId = parameterToIdMap.getInt(mapping.getKey());
            final int valueId = parameterValueToIdMap.get(mapping.getKey()).getInt(mapping.getValue());
            combinationArray[parameterId] = valueId;
        }
        
        return combinationArray;
    }
    
    @Override
    public Combination convertCombination(int[] combination) {
        Preconditions.notNull(combination);
        Preconditions.check(combination.length == model.size());
        
        Combination.Builder combinationBuilder = Combination.combination();
        
        for (int parameterId = 0; parameterId < model.size(); parameterId++) {
            if (combination[parameterId] != CombinationUtil.NO_VALUE) {
                final Parameter parameter = model.getParameters().get(parameterId);
                final Value correspondingValue = parameter.getValues().get(combination[parameterId]);
                
                combinationBuilder.value(parameter, correspondingValue);
            }
        }
        
        return combinationBuilder.build();
    }
    
    @Override
    public int convertParameter(Parameter parameter) {
        Preconditions.notNull(parameter);
        
        return parameterToIdMap.getInt(parameter);
    }
    
    @Override
    public Parameter convertParameter(int parameter) {
        Preconditions.check(parameter >= 0 && parameter < model.size());
        
        return model.getParameters().get(parameter);
    }
    
    @Override
    public int convertValue(Parameter parameter, Value value) {
        Preconditions.notNull(parameter);
        Preconditions.notNull(value);
        
        return parameterValueToIdMap.get(parameter).getInt(value);
    }
    
    @Override
    public Value convertValue(int parameter, int value) {
        Preconditions.check(parameter >= 0);
        Preconditions.check(value >= 0);
        
        return model.getParameters().get(parameter).getValues().get(value);
    }
    
    @Override
    public TupleList convertConstraint(Constraint constraint) {
        Preconditions.notNull(constraint);
        
        return constraintToTuplesListMap.get(constraint);
    }
    
    @Override
    public Constraint convertConstraint(TupleList constraint) {
        Preconditions.notNull(constraint);
        
        return tuplesListToConstraintMap.get(constraint);
    }
}
