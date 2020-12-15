package de.rwth.swc.coffee4j.model.manager;

import de.rwth.swc.coffee4j.model.Combination;

/**
 * An executor for a combinatorial test. This means that a class implementing this interface should be able to
 * tell wether the system behaves correctly for the given {@link Combination}.
 */
@FunctionalInterface
public interface TestInputExecutor {
    
    /**
     * Executes the test with the given test input in form of a {@link Combination}.
     * If the system under test behaves correctly, nothing abnormally should happen and the method finishes,
     * otherwise, any kind of exception can be thrown to indicate a failure.
     *
     * @param testInput to be executed. Must not be {@code null}
     * @throws Exception if the system under test does not behave normally for the given test input
     */
    void execute(Combination testInput) throws Exception;
    
}
