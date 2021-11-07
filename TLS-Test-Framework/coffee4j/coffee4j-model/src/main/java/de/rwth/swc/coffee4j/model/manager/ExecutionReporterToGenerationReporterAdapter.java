package de.rwth.swc.coffee4j.model.manager;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.engine.report.GenerationReporter;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.TestInputGroupContext;
import de.rwth.swc.coffee4j.model.converter.ModelConverter;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

class ExecutionReporterToGenerationReporterAdapter implements GenerationReporter {
    
    private final ExecutionReporter reporter;
    
    private final ArgumentConverter argumentConverter;
    
    private final ModelConverter modelConverter;
    
    private final Map<Object, TestInputGroupContext> testInputGroupContexts = new HashMap<>();
    
    ExecutionReporterToGenerationReporterAdapter(ExecutionReporter reporter, ArgumentConverter argumentConverter, ModelConverter modelConverter) {
        this.reporter = Preconditions.notNull(reporter);
        this.argumentConverter = Preconditions.notNull(argumentConverter);
        this.modelConverter = Preconditions.notNull(modelConverter);
    }
    
    @Override
    public void testInputGroupGenerated(TestInputGroup testInputGroup, TestInputGroupGenerator generator) {
        initializeContext(testInputGroup, generator);
        reporter.testInputGroupGenerated(convertTestInputGroup(testInputGroup), convertCombinations(testInputGroup.getTestInputs()));
    }
    
    private void initializeContext(TestInputGroup testInputGroup, TestInputGroupGenerator generator) {
        final Object identifier = testInputGroup.getIdentifier();
        final Object convertedIdentifier = argumentConverter.canConvert(identifier) ? argumentConverter.convert(identifier) : identifier;
        
        testInputGroupContexts.put(identifier, new TestInputGroupContext(convertedIdentifier, generator));
    }
    
    private TestInputGroupContext convertTestInputGroup(TestInputGroup testInputGroup) {
        return testInputGroupContexts.get(testInputGroup.getIdentifier());
    }
    
    private List<Combination> convertCombinations(List<int[]> combinations) {
        return combinations.stream().map(modelConverter::convertCombination).collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
    }
    
    @Override
    public void testInputGroupFinished(TestInputGroup testInputGroup) {
        reporter.testInputGroupFinished(convertTestInputGroup(testInputGroup));
    }
    
    @Override
    public void faultCharacterizationStarted(TestInputGroup testInputGroup, FaultCharacterizationAlgorithm algorithm) {
        reporter.faultCharacterizationStarted(convertTestInputGroup(testInputGroup), algorithm);
    }
    
    @Override
    public void faultCharacterizationFinished(TestInputGroup testInputGroup, List<int[]> failureInducingCombinations) {
        reporter.faultCharacterizationFinished(convertTestInputGroup(testInputGroup), convertCombinations(failureInducingCombinations));
    }
    
    @Override
    public void faultCharacterizationTestInputsGenerated(TestInputGroup testInputGroup, List<int[]> testInputs) {
        reporter.faultCharacterizationTestInputsGenerated(convertTestInputGroup(testInputGroup), convertCombinations(testInputs));
    }
    
    @Override
    public void report(ReportLevel level, Report report) {
        Preconditions.notNull(level);
        
        if (level.isWorseThanOrEqualTo(reporter.getReportLevel())) {
            report.convertArguments(argumentConverter);
            reporter.report(level, report);
        }
    }
    
    @Override
    public void report(ReportLevel level, Supplier<Report> reportSupplier) {
        Preconditions.notNull(level);
        Preconditions.notNull(reportSupplier);
        
        if (level.isWorseThanOrEqualTo(reporter.getReportLevel())) {
            final Report report = reportSupplier.get();
            report.convertArguments(argumentConverter);
            reporter.report(level, report);
        }
    }
    
}
