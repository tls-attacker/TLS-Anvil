package de.rwth.swc.coffee4j.engine.characterization.aifl;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmTest;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;

class AiflTest implements FaultCharacterizationAlgorithmTest {
    
    @Override
    public FaultCharacterizationAlgorithm provideAlgorithm(FaultCharacterizationConfiguration configuration) {
        return new Aifl(configuration);
    }
    
}
