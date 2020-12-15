package de.rwth.swc.coffee4j.junit.provider.configuration;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmFactory;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.configuration.converter.ConverterLoader;
import de.rwth.swc.coffee4j.junit.provider.configuration.diagnosis.ConflictDetectionConfigurationLoader;
import de.rwth.swc.coffee4j.junit.provider.configuration.reporter.ReporterLoader;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;
import de.rwth.swc.coffee4j.junit.provider.configuration.characterization.FaultCharacterizationAlgorithmLoader;
import de.rwth.swc.coffee4j.junit.provider.configuration.generator.GeneratorLoader;
import de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManagerConfiguration;
import org.junit.jupiter.api.extension.ExtensionContext;

import static de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManagerConfiguration.consumerManagerConfiguration;

/**
 * Provides a new {@link CombinatorialTestConsumerManagerConfiguration} based on further providers and sources
 * which can be registered using annotations. Specifically, this provider lets you configure any
 * {@link GeneratorLoader} for loader all {@link TestInputGroupGenerator},
 * {@link FaultCharacterizationAlgorithmLoader} to load a
 * <p>
 * {@link FaultCharacterizationAlgorithmFactory},
 * {@link ConverterLoader} to add {@link ArgumentConverter} to the default ones,
 * and {@link ReporterLoader} to register custom {@link ExecutionReporter}s which
 * listen during {@link CombinatorialTest} execution and provide valuable feedback.
 */
public class DelegatingConfigurationProvider implements ConfigurationProvider {
    
    @Override
    public CombinatorialTestConsumerManagerConfiguration provide(ExtensionContext extensionContext) {
        return consumerManagerConfiguration()
                .generators(new GeneratorLoader().load(extensionContext))
                .executionReporters(new ReporterLoader().load(extensionContext))
                .faultCharacterizationAlgorithmFactory(new FaultCharacterizationAlgorithmLoader().load(extensionContext))
                .setConflictDetectionConfiguration(new ConflictDetectionConfigurationLoader().load(extensionContext))
                .argumentConverters(new ConverterLoader().load(extensionContext))
                .build();
    }
}
