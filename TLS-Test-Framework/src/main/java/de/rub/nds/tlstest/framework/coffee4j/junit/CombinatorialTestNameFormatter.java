package de.rub.nds.tlstest.framework.coffee4j.junit;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.Value;
import org.junit.platform.commons.util.StringUtils;

import java.util.Map;

/**
 * Formats the name of one test input in a {@link CombinatorialTest} according to the name defined in
 * {@link CombinatorialTest#name()}, the currently tested {@link Combination}, and the test index.
 * <p>
 * Multiple placeholders are supported:
 * -{index}: given the current invocation index of the test starting with 1
 * -{combination}: the complete {@link Combination} which is tested by the test
 * -{PARAMETER_NAME}: the value of the {@link Parameter} with the given name in the
 * currently tested {@link Combination}
 * <p>
 * This class is more a less a copy of {@link org.junit.jupiter.params.ParameterizedTestNameFormatter} from the
 * junit-jupiter-params project.
 */
class CombinatorialTestNameFormatter {
    
    private final String namePattern;
    
    CombinatorialTestNameFormatter(String namePattern) {
        this.namePattern = namePattern;
    }
    
    String format(int invocationIndex, Combination testInput) {
        final String invocationIndexReplacedPattern = replaceInvocationIndex(namePattern, invocationIndex);
        final String parameterNamesReplacedPattern = replaceParameterNamesWithValues(invocationIndexReplacedPattern, testInput);
        
        return replaceCombinations(parameterNamesReplacedPattern, testInput);
    }
    
    private String replaceInvocationIndex(String patter, int invocationIndex) {
        return patter.replace("{index}", Integer.toString(invocationIndex));
    }
    
    private String replaceParameterNamesWithValues(String patter, Combination testInput) {
        for (Map.Entry<Parameter, Value> mapping : testInput.getParameterValueMap().entrySet()) {
            final String currentParameterName = mapping.getKey().getName();
            final String valueAsString = StringUtils.nullSafeToString(mapping.getValue().get());
            patter = patter.replace('{' + currentParameterName + '}', valueAsString);
        }
        
        return patter;
    }
    
    private String replaceCombinations(String pattern, Combination testInput) {
        return pattern.replace("{combination}", testInput.toString());
    }
    
}
