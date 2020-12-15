package de.rwth.swc.coffee4j.engine.manager;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmFactory;
import de.rwth.swc.coffee4j.engine.conflict.ConflictDetectionConfiguration;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.report.GenerationReporter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Collections;

import static de.rwth.swc.coffee4j.engine.conflict.ConflictDetectionConfiguration.disable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CombinatorialTestConfigurationTest {
    
    private static final FaultCharacterizationAlgorithmFactory FACTORY = Mockito.mock(FaultCharacterizationAlgorithmFactory.class);
    
    private static final TestInputGroupGenerator GENERATOR = Mockito.mock(TestInputGroupGenerator.class);
    
    private static final GenerationReporter REPORTER = Mockito.mock(GenerationReporter.class);
    
    @Test
    void preconditions() {
        assertThrows(NullPointerException.class, () -> new CombinatorialTestConfiguration(FACTORY, disable(), null, REPORTER));
        assertThrows(IllegalArgumentException.class, () -> new CombinatorialTestConfiguration(FACTORY, disable(), Collections.singletonList(null), REPORTER));
    }
    
    @Test
    void optionalNotPresentIfFactoryNull() {
        final CombinatorialTestConfiguration configuration = new CombinatorialTestConfiguration(null, disable(), Collections.singletonList(GENERATOR), REPORTER);
        
        assertFalse(configuration.getFaultCharacterizationAlgorithmFactory().isPresent());
        assertEquals(Collections.singletonList(GENERATOR), configuration.getGenerators());
        Assertions.assertEquals(REPORTER, configuration.getGenerationReporter().orElse(null));
    }
    
    @Test
    void optionalNotPresentIfReporterNull() {
        final CombinatorialTestConfiguration configuration = new CombinatorialTestConfiguration(FACTORY, disable(), Collections.singletonList(GENERATOR), null);
        
        assertFalse(configuration.getGenerationReporter().isPresent());
        assertEquals(Collections.singletonList(GENERATOR), configuration.getGenerators());
        Assertions.assertEquals(FACTORY, configuration.getFaultCharacterizationAlgorithmFactory().orElse(null));
    }
    
}
