package de.rwth.swc.coffee4j.engine.characterization.ben;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmTest;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;

class BenTest implements FaultCharacterizationAlgorithmTest {
    
    @Override
    public FaultCharacterizationAlgorithm provideAlgorithm(FaultCharacterizationConfiguration configuration) {
        return new Ben(configuration, 10, 50);
    }
    
}
