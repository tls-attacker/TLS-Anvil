/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.simpleTest;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlstest.framework.coffee4j.junit.TlsTestCombinatorialTestNameFormatter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;

/** */
public class SimpleTestInvocationContext implements TestTemplateInvocationContext {

    private final TlsTestCombinatorialTestNameFormatter nameFormatter;

    private final List<DerivationParameter> testInput;

    public SimpleTestInvocationContext(DerivationParameter testInput) {
        this();
        this.testInput.add(testInput);
    }

    public SimpleTestInvocationContext() {
        this.testInput = new LinkedList<>();
        this.nameFormatter = new TlsTestCombinatorialTestNameFormatter("[{index}] {combination}");
    }

    @Override
    public String getDisplayName(int invocationIndex) {
        return nameFormatter.format(invocationIndex, testInput);
    }

    @Override
    public List<Extension> getAdditionalExtensions() {
        return Arrays.asList(
                new SimpleTestParameterResolver(testInput), new SimpleTestExecutionCallback());
    }
}
