package de.rwth.swc.coffee4j.model.converter;

import de.rwth.swc.coffee4j.model.InputParameterModel;

/**
 * Factory for creating new {@link ModelConverter} instances based on an {@link InputParameterModel}.
 */
@FunctionalInterface
public interface ModelConverterFactory {
    
    /**
     * Creates a new {@link ModelConverter} which converts the given testModel and its parameters, values, and constraints.
     *
     * @param model the testModel
     * @return a converter for the testModel
     */
    ModelConverter create(InputParameterModel model);
    
}
