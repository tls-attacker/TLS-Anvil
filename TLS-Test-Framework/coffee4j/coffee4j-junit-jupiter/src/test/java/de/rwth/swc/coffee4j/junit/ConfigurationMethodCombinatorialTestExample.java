package de.rwth.swc.coffee4j.junit;

import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.configuration.ConfigurationFromMethod;
import de.rwth.swc.coffee4j.junit.provider.model.ModelFromMethod;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManagerConfiguration;
import de.rwth.swc.coffee4j.model.report.PrintStreamExecutionReporter;

import java.util.Arrays;
import java.util.Collections;

import static de.rwth.swc.coffee4j.model.InputParameterModel.inputParameterModel;
import static de.rwth.swc.coffee4j.model.Parameter.parameter;
import static de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManagerConfiguration.consumerManagerConfiguration;

/**
 * Demonstrates that a custom configuration can be provided for a {@link CombinatorialTest} using
 * {@link ConfigurationFromMethod}. To see that this really does use the configuration from the method,
 * it only has one generator producing a single test input. The normal default would be IPOG, which would generate
 * two test inputs.
 */
class ConfigurationMethodCombinatorialTestExample {
    
    @CombinatorialTest
    @ModelFromMethod("testModel")
    @ConfigurationFromMethod("testConfiguration")
    void test(String param1) {
        System.out.println(param1);
    }
    
    private static InputParameterModel testModel() {
        return inputParameterModel("test").strength(1).parameter(parameter("param1").values("0", "1")).build();
    }
    
    private static CombinatorialTestConsumerManagerConfiguration testConfiguration() {
        return consumerManagerConfiguration().generator((model, reporter) -> Collections.singletonList(() -> new TestInputGroup(0, Arrays.asList(new int[]{0})))).executionReporter(new PrintStreamExecutionReporter()).build();
    }
    
}
