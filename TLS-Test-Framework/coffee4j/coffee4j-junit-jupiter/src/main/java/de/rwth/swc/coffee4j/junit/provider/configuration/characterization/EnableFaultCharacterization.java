package de.rwth.swc.coffee4j.junit.provider.configuration.characterization;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmFactory;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This is a {@link FaultCharacterizationAlgorithmFactorySource} which uses the {@link ConstructorBasedFaultCharacterizationProvider} to create
 * new instances of a {@link FaultCharacterizationAlgorithmFactory} by instantiation
 * the respective {@link FaultCharacterizationAlgorithm} class via constructor accepting exactly one
 * {@link FaultCharacterizationConfiguration}.
 * This means that not a {@link FaultCharacterizationAlgorithmFactory} is needed
 * in the {@link #value()} method, but instead a normal {@link FaultCharacterizationAlgorithm} which can be instantiated
 * multiple times, thus creating a {@link FaultCharacterizationAlgorithmFactory}.
 */
@Target({ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@FaultCharacterizationAlgorithmFactorySource(ConstructorBasedFaultCharacterizationProvider.class)
public @interface EnableFaultCharacterization {
    
    /**
     * @return the class of a {@link FaultCharacterizationAlgorithm} which has a constructor with just one
     * {@link FaultCharacterizationConfiguration} parameter
     */
    Class<? extends FaultCharacterizationAlgorithm> value();
}
