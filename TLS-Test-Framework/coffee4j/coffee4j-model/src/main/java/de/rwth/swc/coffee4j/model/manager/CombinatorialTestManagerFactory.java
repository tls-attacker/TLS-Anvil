package de.rwth.swc.coffee4j.model.manager;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.manager.CombinatorialTestConfiguration;
import de.rwth.swc.coffee4j.engine.manager.CombinatorialTestManager;
import de.rwth.swc.coffee4j.model.InputParameterModel;

import java.util.function.BiFunction;

/**
 * A factory for creating new {@link CombinatorialTestManager} instances from a given configuration.
 * This is needed to reuse {@link CombinatorialTestConsumerManagerConfiguration} instances, as they can now
 * be reused for multiple {@link InputParameterModel}s.
 */
@FunctionalInterface
public interface CombinatorialTestManagerFactory extends BiFunction<CombinatorialTestConfiguration, TestModel, CombinatorialTestManager> {
}
