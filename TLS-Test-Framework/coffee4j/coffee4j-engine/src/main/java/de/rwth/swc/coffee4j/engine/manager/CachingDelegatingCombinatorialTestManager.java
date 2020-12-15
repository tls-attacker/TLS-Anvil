package de.rwth.swc.coffee4j.engine.manager;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.conflict.DiagnosisHittingSet;
import de.rwth.swc.coffee4j.engine.conflict.MissingInvalidTuple;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A {@link CombinatorialTestManager} which does not generate test inputs by itself but delegates this to another
 * manager. However, it does add caching capability to any given manager. This means no test input is returned twice
 * across all two methods. For example, if the initial test input [0, 0, 0] has been returned, it will not be returned
 * again for fault characterization. Instead the cached result is used.
 * With an appropriate cache, results can even be shared over multiple runs if that should ever be desirable.
 */
public class CachingDelegatingCombinatorialTestManager implements CombinatorialTestManager {
    
    private final TestResultCache cache;
    
    private final CombinatorialTestManager generator;
    
    private final Set<IntArrayWrapper> awaitedTestResults = new HashSet<>();
    
    public CachingDelegatingCombinatorialTestManager(TestResultCache cache, CombinatorialTestManager generator) {
        this.cache = Preconditions.notNull(cache);
        this.generator = Preconditions.notNull(generator);
    }

    @Override
    public List<MissingInvalidTuple> checkConstraintsForConflicts() {
        return generator.checkConstraintsForConflicts();
    }

    @Override
    public List<DiagnosisHittingSet> computeMinimalDiagnosisHittingSets(List<MissingInvalidTuple> missingInvalidTuples) {
        return generator.computeMinimalDiagnosisHittingSets(missingInvalidTuples);
    }

    @Override
    public synchronized List<int[]> generateInitialTests() {
        return computeTestInputsWithUnknownResults(generator.generateInitialTests());
    }
    
    private List<int[]> computeTestInputsWithUnknownResults(List<int[]> neededTestResults) {
        final List<int[]> testInputsWithUnknownResults = new ArrayList<>();
        final LinkedList<IntArrayWrapper> remainingNeededTestResults = neededTestResults.stream().map(IntArrayWrapper::new).distinct().collect(Collectors.toCollection(LinkedList::new));
        
        while (!remainingNeededTestResults.isEmpty()) {
            final IntArrayWrapper neededTestResult = remainingNeededTestResults.poll();
            if (cache.containsResultFor(neededTestResult)) {
                final TestResult testResult = cache.getResultFor(neededTestResult);
                generator.generateAdditionalTestInputsWithResult(neededTestResult.getArray(), testResult).stream().map(IntArrayWrapper::new).distinct().forEach(remainingNeededTestResults::push);
            } else if (!awaitedTestResults.contains(neededTestResult)) {
                testInputsWithUnknownResults.add(neededTestResult.getArray());
                awaitedTestResults.add(neededTestResult);
            }
        }
        
        return testInputsWithUnknownResults;
    }
    
    @Override
    public synchronized List<int[]> generateAdditionalTestInputsWithResult(int[] testInput, TestResult testResult) {
        final IntArrayWrapper wrappedTestInput = IntArrayWrapper.wrap(testInput);
        awaitedTestResults.remove(wrappedTestInput);
        cache.addResultFor(wrappedTestInput, testResult);
        
        return computeTestInputsWithUnknownResults(generator.generateAdditionalTestInputsWithResult(testInput, testResult));
    }
}
