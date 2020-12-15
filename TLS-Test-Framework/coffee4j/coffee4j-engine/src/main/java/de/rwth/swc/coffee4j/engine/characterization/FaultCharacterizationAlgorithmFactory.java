package de.rwth.swc.coffee4j.engine.characterization;

import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;

/**
 * Marks factories used to create fault characterization algorithms for a given configuration. This is used to create
 * different fault characterization algorithms for all {@link TestInputGroup} in
 * a combinatorial test.
 */
@FunctionalInterface
public interface FaultCharacterizationAlgorithmFactory {
    
    /**
     * Creates a new algorithm for the given configuration.
     *
     * @param configuration contains all important general information with which additional test inputs can be
     *                      generated. This includes constraints checkers and general testModel information. Must not be {@code null}
     * @return a algorithm conforming to the configuration
     */
    FaultCharacterizationAlgorithm create(FaultCharacterizationConfiguration configuration);
    
}
