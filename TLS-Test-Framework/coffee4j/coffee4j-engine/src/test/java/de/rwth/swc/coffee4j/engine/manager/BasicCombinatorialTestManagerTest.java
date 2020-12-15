package de.rwth.swc.coffee4j.engine.manager;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmFactory;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.report.GenerationReporter;
import de.rwth.swc.coffee4j.engine.report.Reporter;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import static de.rwth.swc.coffee4j.engine.conflict.ConflictDetectionConfiguration.disable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BasicCombinatorialTestManagerTest {
    
    private GenerationReporter generationReporter;
    
    @BeforeEach
    void instantiateMocks() {
        generationReporter = Mockito.mock(GenerationReporter.class);
    }
    
    @Test
    void preconditions() {
        assertThrows(NullPointerException.class, () -> new BasicCombinatorialTestManager(null, simpleModel()));
        assertThrows(NullPointerException.class, () -> new BasicCombinatorialTestManager(simpleConfiguration(), null));
    }
    
    private TestModel simpleModel() {
        return new TestModel(1, new int[]{2}, Collections.emptyList(), Collections.emptyList());
    }
    
    private CombinatorialTestConfiguration simpleConfiguration() {
        return new CombinatorialTestConfiguration(null, disable(), Collections.emptyList(), generationReporter);
    }
    
    @Test
    void returnsListOfTestInputsFromOneGeneratorInInitialGeneration() {
        final List<int[]> testInputs = Arrays.asList(new int[]{0}, new int[]{1});
        final TestInputGroup group = new TestInputGroup("test", testInputs);
        final Supplier<TestInputGroup> groupSupplier = () -> group;
        final Set<Supplier<TestInputGroup>> allGroups = Collections.singleton(groupSupplier);
        final TestInputGroupGenerator generator = Mockito.mock(TestInputGroupGenerator.class);
        when(generator.generate(any(), any())).thenReturn(allGroups);
        
        final CombinatorialTestConfiguration configuration = new CombinatorialTestConfiguration(null, disable(), Collections.singleton(generator), generationReporter);
        final TestModel model = new TestModel(1, new int[]{2}, Collections.emptyList(), Collections.emptyList());
        final BasicCombinatorialTestManager testInputGenerator = new BasicCombinatorialTestManager(configuration, model);
        
        final List<int[]> generatedTestInputs = testInputGenerator.generateInitialTests();
        
        Assertions.assertEquals(IntArrayWrapper.wrapToSet(testInputs), IntArrayWrapper.wrapToSet(generatedTestInputs));
        assertEquals(Collections.emptyList(), testInputGenerator.generateAdditionalTestInputsWithResult(testInputs.get(0), TestResult.failure(new IllegalArgumentException())));
        assertEquals(Collections.emptyList(), testInputGenerator.generateAdditionalTestInputsWithResult(testInputs.get(1), TestResult.failure(new IllegalArgumentException())));
        
        verify(generator, times(1)).generate(eq(model), any());
        verify(generationReporter, times(1)).testInputGroupFinished(group);
    }
    
    @Test
    @SuppressWarnings("unchecked")
    void faultCharacterizationUsedWhenAlgorithmAvailable() {
        final List<int[]> testInputs = Arrays.asList(new int[]{0}, new int[]{1});
        final List<int[]> characterizationTestInputs = Arrays.asList(new int[]{2});
        final FaultCharacterizationConfiguration characterizationConfiguration = new FaultCharacterizationConfiguration(Mockito.mock(TestModel.class), Mockito.mock(Reporter.class));
        final TestInputGroup group = new TestInputGroup("test", testInputs, characterizationConfiguration);
        final Supplier<TestInputGroup> groupSupplier = () -> group;
        final Set<Supplier<TestInputGroup>> allGroups = Collections.singleton(groupSupplier);
        final TestInputGroupGenerator generator = Mockito.mock(TestInputGroupGenerator.class);
        when(generator.generate(any(), any())).thenReturn(allGroups);
        
        final FaultCharacterizationAlgorithm algorithm = Mockito.mock(FaultCharacterizationAlgorithm.class);
        final FaultCharacterizationAlgorithmFactory factory = Mockito.mock(FaultCharacterizationAlgorithmFactory.class);
        when(factory.create(any())).thenReturn(algorithm);
        when(algorithm.computeNextTestInputs(any())).thenReturn(characterizationTestInputs);
        
        final CombinatorialTestConfiguration configuration = new CombinatorialTestConfiguration(factory, disable(), Collections.singleton(generator), generationReporter);
        final TestModel testModel = new TestModel(1, new int[]{3}, Collections.emptyList(), Collections.emptyList());
        final BasicCombinatorialTestManager testInputGenerator = new BasicCombinatorialTestManager(configuration, testModel);
        
        final List<int[]> generatedTestInputs = testInputGenerator.generateInitialTests();
        final Exception exception = new IllegalArgumentException();
        Assertions.assertEquals(IntArrayWrapper.wrapToSet(testInputs), IntArrayWrapper.wrapToSet(generatedTestInputs));
        assertEquals(Collections.emptyList(), testInputGenerator.generateAdditionalTestInputsWithResult(testInputs.get(0), TestResult.failure(exception)));
        
        final List<int[]> generatedCharacterizationTestInputs = testInputGenerator.generateAdditionalTestInputsWithResult(testInputs.get(1), TestResult.success());
        
        Assertions.assertEquals(IntArrayWrapper.wrapToSet(characterizationTestInputs), IntArrayWrapper.wrapToSet(generatedCharacterizationTestInputs));
        
        final ArgumentCaptor<Map<int[], TestResult>> mapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(algorithm, times(1)).computeNextTestInputs(mapCaptor.capture());
        verify(factory, times(1)).create(characterizationConfiguration);
        final Map<int[], TestResult> map = mapCaptor.getValue();
        
        final List<int[]> keys = new ArrayList<>(map.keySet());
        assertEquals(2, keys.size());
        assertTrue(map.containsValue(TestResult.success()));
        assertTrue(map.containsValue(TestResult.failure(exception)));
        Assertions.assertTrue(IntArrayWrapper.wrapToSet(keys).contains(IntArrayWrapper.wrap(testInputs.get(0))));
        Assertions.assertTrue(IntArrayWrapper.wrapToSet(keys).contains(IntArrayWrapper.wrap(testInputs.get(1))));
    }
    
}
