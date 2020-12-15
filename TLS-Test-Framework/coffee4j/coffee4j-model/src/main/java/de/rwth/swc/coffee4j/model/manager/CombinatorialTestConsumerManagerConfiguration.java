package de.rwth.swc.coffee4j.model.manager;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmFactory;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.manager.CombinatorialTestManager;
import de.rwth.swc.coffee4j.engine.manager.BasicCombinatorialTestManager;
import de.rwth.swc.coffee4j.engine.manager.CachingDelegatingCombinatorialTestManager;
import de.rwth.swc.coffee4j.engine.manager.HashMapTestResultCache;
import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.converter.IndexBasedModelConverter;
import de.rwth.swc.coffee4j.model.converter.ModelConverter;
import de.rwth.swc.coffee4j.model.converter.ModelConverterFactory;
import de.rwth.swc.coffee4j.engine.conflict.ConflictDetectionConfiguration;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The complete reusable part of the configuration for a combinatorial test input. This means that multiple combinatorial
 * tests can be executed with the same {@link CombinatorialTestConsumerManagerConfiguration}, as generally only
 * the testModel changes.
 * Includes a factory for creating a {@link CombinatorialTestManager},
 * {@link ModelConverter},
 * {@link FaultCharacterizationAlgorithm}s, generators for initial test inputs,
 * reporters and converters.
 */
public final class CombinatorialTestConsumerManagerConfiguration {
    
    private final CombinatorialTestManagerFactory managerFactory;
    
    private final ModelConverterFactory modelConverterFactory;

    private final ConflictDetectionConfiguration conflictDetectionConfiguration;

    private final FaultCharacterizationAlgorithmFactory characterizationAlgorithmFactory;
    
    private final List<TestInputGroupGenerator> generators;
    
    private final List<ExecutionReporter> executionReporters;
    
    private final List<ArgumentConverter> argumentConverters;
    
    private CombinatorialTestConsumerManagerConfiguration(Builder builder) {
        managerFactory = builder.managerFactory;
        modelConverterFactory = Preconditions.notNull(builder.modelConverterFactory);
        conflictDetectionConfiguration = builder.conflictDetectionConfiguration;
        characterizationAlgorithmFactory = builder.characterizationAlgorithmFactory;
        generators = builder.generators;
        executionReporters = builder.executionReporters;
        argumentConverters = builder.argumentConverters;
    }
    
    /**
     * @return the factory used to create a new manager for a combinatorial test
     */
    public CombinatorialTestManagerFactory getManagerFactory() {
        return managerFactory;
    }
    
    /**
     * @return the factory used to create a new manager for an input parameter testModel
     */
    public ModelConverterFactory getModelConverterFactory() {
        return modelConverterFactory;
    }

    public ConflictDetectionConfiguration getConflictDetectionConfiguration()  {
        return conflictDetectionConfiguration;
    }

    /**
     * @return an optional containing the factory for creating new characterization algorithms if one is configured,
     * otherwise and empty {@link Optional} is returned
     */
    public Optional<FaultCharacterizationAlgorithmFactory> getCharacterizationAlgorithmFactory() {
        return Optional.ofNullable(characterizationAlgorithmFactory);
    }
    
    /**
     * @return all generators which should be used for generating initial test inputs. May be empty
     */
    public List<TestInputGroupGenerator> getGenerators() {
        return generators;
    }
    
    /**
     * @return all reporter for listening to interesting events during the generating and execution. May be empty
     */
    public List<ExecutionReporter> getExecutionReporters() {
        return executionReporters;
    }
    
    /**
     * @return all argument converter for converting reports and identifiers for test input groups. May be empty
     */
    public List<ArgumentConverter> getArgumentConverters() {
        return argumentConverters;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CombinatorialTestConsumerManagerConfiguration that = (CombinatorialTestConsumerManagerConfiguration) o;
        return Objects.equals(managerFactory, that.managerFactory) &&
                Objects.equals(modelConverterFactory, that.modelConverterFactory) &&
                Objects.equals(conflictDetectionConfiguration, that.conflictDetectionConfiguration) &&
                Objects.equals(characterizationAlgorithmFactory, that.characterizationAlgorithmFactory) &&
                Objects.equals(generators, that.generators) &&
                Objects.equals(executionReporters, that.executionReporters) &&
                Objects.equals(argumentConverters, that.argumentConverters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(managerFactory, modelConverterFactory, conflictDetectionConfiguration, characterizationAlgorithmFactory, generators, executionReporters, argumentConverters);
    }

    @Override
    public String toString() {
        return "CombinatorialTestConsumerManagerConfiguration{" +
                "managerFactory=" + managerFactory +
                ", modelConverterFactory=" + modelConverterFactory +
                ", conflictDetectionConfiguration=" + conflictDetectionConfiguration +
                ", characterizationAlgorithmFactory=" + characterizationAlgorithmFactory +
                ", generators=" + generators +
                ", executionReporters=" + executionReporters +
                ", argumentConverters=" + argumentConverters +
                '}';
    }

    public static Builder consumerManagerConfiguration() {
        return new Builder();
    }
    
    /**
     * The realization of the builder pattern for a quick and readable construction of a new configuration.
     */
    public static final class Builder {
        
        private CombinatorialTestManagerFactory managerFactory = (configuration, generationReporter) -> new CachingDelegatingCombinatorialTestManager(new HashMapTestResultCache(), new BasicCombinatorialTestManager(configuration, generationReporter));
        
        private ModelConverterFactory modelConverterFactory = IndexBasedModelConverter::new;
        
        private FaultCharacterizationAlgorithmFactory characterizationAlgorithmFactory;

        private ConflictDetectionConfiguration conflictDetectionConfiguration;

        private final List<TestInputGroupGenerator> generators = new ArrayList<>();
        
        private final List<ExecutionReporter> executionReporters = new ArrayList<>();
        
        private final List<ArgumentConverter> argumentConverters = new ArrayList<>();
        
        /**
         * Sets which factory shall be used to create new
         * {@link CombinatorialTestManager} instances. The default creates new ones
         * using a {@link CachingDelegatingCombinatorialTestManager} with a {@link HashMapTestResultCache} wrapped
         * around a {@link BasicCombinatorialTestManager}.
         *
         * @param managerFactory the factory for creating new managers. Must not be {@code null} when
         *                       {@link #build()} is called
         * @return this
         */
        public Builder managerFactory(CombinatorialTestManagerFactory managerFactory) {
            this.managerFactory = managerFactory;

            return this;
        }
        
        /**
         * Sets which factory shall be used to create new {@link ModelConverter}
         * instances. The default is a {@link IndexBasedModelConverter}.
         *
         * @param modelConverterFactory the factory for creating new converters. Must not be {@code null} when
         *                              {@link #build()} is called
         * @return this
         */
        public Builder modelConverterFactory(ModelConverterFactory modelConverterFactory) {
            this.modelConverterFactory = modelConverterFactory;
            
            return this;
        }
        
        /**
         * Sets which factory shall be used to create new
         * {@link FaultCharacterizationAlgorithm} instances during combinatorial
         * testing. The default value is {@code null}, which means no fault characterization will be used.
         *
         * @param characterizationAlgorithmFactory the factory for creating new converters. Can be {@code null} when calling
         *                                         {@link #build()} to indicate that no fault characterization is used
         * @return this
         */
        public Builder faultCharacterizationAlgorithmFactory(FaultCharacterizationAlgorithmFactory characterizationAlgorithmFactory) {
            this.characterizationAlgorithmFactory = characterizationAlgorithmFactory;
            
            return this;
        }


        public Builder setConflictDetectionConfiguration(ConflictDetectionConfiguration constraintDiagnosisEnabled) {
            this.conflictDetectionConfiguration = constraintDiagnosisEnabled;

            return this;
        }

        /**
         * Adds one execution reporter to listen to important events during combinatorial test execution.
         *
         * @param executionReporter the reporter to be added. Must not be {@code null}
         * @return this
         */
        public Builder executionReporter(ExecutionReporter executionReporter) {
            executionReporters.add(Preconditions.notNull(executionReporter));
            
            return this;
        }
        
        /**
         * Adds all execution reports to listen to important events during combinatorial test execution.
         *
         * @param executionReporters the reporters to be added. Must not be, nor contain {@code null}
         * @return this
         */
        public Builder executionReporters(ExecutionReporter... executionReporters) {
            Preconditions.notNull(executionReporters);
            
            for (ExecutionReporter executionReporter : executionReporters) {
                this.executionReporters.add(Preconditions.notNull(executionReporter));
            }
            
            return this;
        }
        
        /**
         * Adds all execution reporters to listen to important events during combinatorial test execution.
         *
         * @param executionReporters the reporters to be added. Must not be, nor contain {@code null}
         * @return this
         */
        public Builder executionReporters(Collection<ExecutionReporter> executionReporters) {
            Preconditions.notNull(executionReporters);
            Preconditions.check(!executionReporters.contains(null));
            
            this.executionReporters.addAll(executionReporters);
            
            return this;
        }
        
        /**
         * Adds the argument converter to convert report arguments from engine to testModel representations.
         *
         * @param argumentConverter the converter to be added. Must not be {@code null}
         * @return this
         */
        public Builder argumentConverter(ArgumentConverter argumentConverter) {
            argumentConverters.add(Preconditions.notNull(argumentConverter));
            
            return this;
        }
        
        /**
         * Adds the argument converters to convert report arguments from engine to testModel representations.
         *
         * @param arguementConverters the converters to be added. Must not be, nor contain {@code null}
         * @return this
         */
        public Builder argumentConverters(ArgumentConverter... arguementConverters) {
            Preconditions.notNull(arguementConverters);
            
            for (ArgumentConverter argumentConverter : arguementConverters) {
                this.argumentConverters.add(Preconditions.notNull(argumentConverter));
            }
            
            return this;
        }
        
        /**
         * Adds the argument converters to convert report arguments from engine to testModel representations.
         *
         * @param argumentConverters the converters to be added. Must not be, nor contain {@code null}
         * @return this
         */
        public Builder argumentConverters(Collection<ArgumentConverter> argumentConverters) {
            Preconditions.notNull(argumentConverters);
            Preconditions.check(!argumentConverters.contains(null));
            
            this.argumentConverters.addAll(argumentConverters);
            
            return this;
        }
        
        /**
         * Adds one generator for initial {@link TestInputGroup} generation.
         *
         * @param generator the generator to be added. Must not be {@code null}
         * @return this
         */
        public Builder generator(TestInputGroupGenerator generator) {
            generators.add(Preconditions.notNull(generator));
            
            return this;
        }
        
        /**
         * Adds all generators for initial {@link TestInputGroup} generation.
         *
         * @param generators the generators to be added. Must not be, nor contain {@code null}
         * @return this
         */
        public Builder generators(TestInputGroupGenerator... generators) {
            Preconditions.notNull(generators);
            
            for (TestInputGroupGenerator generator : generators) {
                this.generators.add(Preconditions.notNull(generator));
            }
            
            return this;
        }
        
        /**
         * Adds all generators for initial {@link TestInputGroup} generation.
         *
         * @param generators the generators to be added. Must not be, nor contain {@code null}
         * @return this
         */
        public Builder generators(Collection<TestInputGroupGenerator> generators) {
            Preconditions.notNull(generators);
            Preconditions.check(!generators.contains(null));
            
            this.generators.addAll(generators);
            
            return this;
        }
        
        /**
         * Creates a new configuration based on the supplied values.
         * The {@link #managerFactory(CombinatorialTestManagerFactory)} and
         * {@link #modelConverterFactory(ModelConverterFactory)} must not be {@code null}. If they are not used,
         * they will have the non-{@code null} default values defined at the methods.
         *
         * @return the new configuration
         */
        public CombinatorialTestConsumerManagerConfiguration build() {
            return new CombinatorialTestConsumerManagerConfiguration(this);
        }
    }
}
