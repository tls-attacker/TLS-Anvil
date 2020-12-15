package de.rwth.swc.coffee4j.engine.characterization.delta;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmTest;

class ImprovedDeltaDebuggingTest implements FaultCharacterizationAlgorithmTest {
    
    @Override
    public FaultCharacterizationAlgorithm provideAlgorithm(FaultCharacterizationConfiguration configuration) {
        return new ImprovedDeltaDebugging(configuration);
    }
    
}
