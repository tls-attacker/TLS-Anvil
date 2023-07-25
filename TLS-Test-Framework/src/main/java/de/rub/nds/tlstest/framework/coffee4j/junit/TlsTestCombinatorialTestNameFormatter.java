package de.rub.nds.tlstest.framework.coffee4j.junit;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlstest.framework.anvil.TlsParameterCombination;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.CombinatorialTestNameFormatter;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.Value;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.junit.platform.commons.util.StringUtils;

/**
 * Formats the name of one test input in a {@link CombinatorialTest} according to the name defined
 * in {@link CombinatorialTest#name()}, the currently tested {@link Combination}, and the test
 * index.
 *
 * <p>Multiple placeholders are supported: -{index}: given the current invocation index of the test
 * starting with 1 -{combination}: the complete {@link Combination} which is tested by the test
 * -{PARAMETER_NAME}: the value of the {@link Parameter} with the given name in the currently tested
 * {@link Combination}
 *
 * <p>This class is more a less a copy of {@link
 * org.junit.jupiter.params.ParameterizedTestNameFormatter} from the junit-jupiter-params project.
 */
public class TlsTestCombinatorialTestNameFormatter extends CombinatorialTestNameFormatter {

    public TlsTestCombinatorialTestNameFormatter(String namePattern) {
        super(namePattern);
    }

    @Override
    public String format(int invocationIndex, Combination testInput) {
        final String invocationIndexReplacedPattern =
                replaceInvocationIndex(namePattern, invocationIndex);
        final String parameterNamesReplacedPattern =
                replaceParameterNamesWithValues(invocationIndexReplacedPattern, testInput);

        return replaceCombinations(parameterNamesReplacedPattern, testInput);
    }

    public String format(int invocationIndex, List<DerivationParameter> testInput) {
        final String invocationIndexReplacedPattern =
                replaceInvocationIndex(namePattern, invocationIndex);
        return replaceCombinations(invocationIndexReplacedPattern, testInput);
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
        return pattern.replace(
                "{combination}", TlsParameterCombination.fromCombination(testInput).toString());
    }

    private String replaceCombinations(String pattern, List<DerivationParameter> testInput) {
        return pattern.replace(
                "{combination}",
                new TlsParameterCombination(new LinkedList<>(testInput)).toString());
    }
}
