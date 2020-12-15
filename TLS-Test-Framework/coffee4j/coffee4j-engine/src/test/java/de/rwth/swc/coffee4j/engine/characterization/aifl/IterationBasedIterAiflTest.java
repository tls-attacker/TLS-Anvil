package de.rwth.swc.coffee4j.engine.characterization.aifl;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmTest;

class IterationBasedIterAiflTest implements FaultCharacterizationAlgorithmTest {
    
    @Override
    public FaultCharacterizationAlgorithm provideAlgorithm(FaultCharacterizationConfiguration configuration) {
        return new IterationBasedIterAifl(configuration);
    }
    
}
