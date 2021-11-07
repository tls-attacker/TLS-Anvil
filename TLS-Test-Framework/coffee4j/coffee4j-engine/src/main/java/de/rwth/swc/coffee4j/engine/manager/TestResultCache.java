package de.rwth.swc.coffee4j.engine.manager;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;

/**
 * A cache for test results to reduce unnecessary execution time if the same test input results are requested multiple
 * times.
 */
public interface TestResultCache {
    
    /**
     * @param testInput for which a result could be needed. Must not be {@code null}
     * @return Whether the cache contains the result of the given test input
     * @throws NullPointerException if testInput is {@code null}
     */
    boolean containsResultFor(IntArrayWrapper testInput);
    
    /**
     * @param testInput for which the result is needed. Must not be {@code null}
     * @return the result of the given test input. If
     * {@link #containsResultFor(IntArrayWrapper)} returns {@code false} for this test input, the behavior is not
     * defined and depends on the actual implementation
     * @throws NullPointerException if testInput is {@code null}
     */
    TestResult getResultFor(IntArrayWrapper testInput);
    
    /**
     * Adds a result to the cache so it may later be retrieved via {@link #getResultFor(IntArrayWrapper)}.
     * After a testInput has been added here, {@link #containsResultFor(IntArrayWrapper)} should returned {@code true}
     * if called for the same testInput.
     *
     * @param testInput for which the result should be saved
     * @param result    of the test input
     */
    void addResultFor(IntArrayWrapper testInput, TestResult result);
    
}
