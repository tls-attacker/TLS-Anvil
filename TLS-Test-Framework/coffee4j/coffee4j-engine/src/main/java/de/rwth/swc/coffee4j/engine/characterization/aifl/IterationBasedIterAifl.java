package de.rwth.swc.coffee4j.engine.characterization.aifl;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmFactory;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;

import java.util.List;
import java.util.Map;

/**
 * Extension to the AIFL algorithm based on "Adaptive Interaction Fault Location Based on Combinatorial Testing".
 * In each new iteration, test inputs are generated based on the failed test inputs of the previous generation.
 * The algorithm stops if there either were no failed test inputs in the last iteration, or the number of iterations
 * is now greater than the testing strength, or if the number of suspicious combinations did not change during the
 * last iteration, or if the number of iterations is below a defined threshold (default: 1).
 * Consequently, the algorithm always terminates.
 * <p>
 * Important Information:
 * -Generates many additional test inputs if there are many parameters
 * -Generates many additional test inputs if there are many failing test inputs
 * -Does not order failure-inducing combinations by probability and can return quite a few of them
 * -Does not consider constraints
 * -Is a bit more exact than AIFL itself, but needs considerably more test inputs
 */
public class IterationBasedIterAifl extends Aifl {
    
    private static final int DEFAULT_SUSPICIOUS_COMBINATIONS_THRESHOLD = 1;
    
    private final int suspiciousCombinationsThreshold;
    
    private int iteration = 1;
    
    /**
     * Creates a new IterAIFL algorithm based on the given configuration. The ConstraintsChecker is ignored.
     *
     * @param configuration the configuration for the algorithm
     */
    public IterationBasedIterAifl(FaultCharacterizationConfiguration configuration) {
        this(configuration, DEFAULT_SUSPICIOUS_COMBINATIONS_THRESHOLD);
    }
    
    /**
     * Creates a new IterAIFL algorithm based on the given configuration. The ConstraintsChecker is ignored.
     * The threshold is used as a stopping conditions as described in {@link IterationBasedIterAifl}.
     *
     * @param configuration                   the configuration for the algorithm
     * @param suspiciousCombinationsThreshold the threshold for algorithm termination
     */
    public IterationBasedIterAifl(FaultCharacterizationConfiguration configuration, int suspiciousCombinationsThreshold) {
        super(configuration);
        this.suspiciousCombinationsThreshold = suspiciousCombinationsThreshold;
    }
    
    /**
     * @return a factory always returning new instances of the IterAIFL algorithm
     */
    public static FaultCharacterizationAlgorithmFactory iterAifl() {
        return Aifl::new;
    }
    
    /**
     * Creates a factory which uses the given threshold to configuration the IterAIFL algorithm.
     *
     * @param suspiciousCombinationsThreshold the threshold as described in {@link IterationBasedIterAifl}
     * @return a factory always returning new instances of the IterAIFL algorithm with the given threshold
     */
    public static FaultCharacterizationAlgorithmFactory iterAifl(int suspiciousCombinationsThreshold) {
        return configuration -> new IterationBasedIterAifl(configuration, suspiciousCombinationsThreshold);
    }
    
    @Override
    public boolean shouldGenerateFurtherTestInputs() {
        return iteration < getModel().getNumberOfParameters() && suspiciousCombinations.size() > suspiciousCombinationsThreshold && previousSuspiciousCombinations.size() != suspiciousCombinations.size();
    }
    
    @Override
    public List<IntArrayWrapper> generateNextTestInputs(Map<int[], TestResult> newTestResults) {
        iteration++;
        return super.generateNextTestInputs(newTestResults);
    }
    
}
