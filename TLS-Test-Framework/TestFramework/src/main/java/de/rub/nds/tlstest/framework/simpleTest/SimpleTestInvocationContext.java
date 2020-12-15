package de.rub.nds.tlstest.framework.simpleTest;

import de.rub.nds.tlstest.framework.coffee4j.junit.TlsTestCombinatorialTestNameFormatter;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;

/**
 *
 */
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
        return Arrays.asList(new SimpleTestParameterResolver(testInput), new SimpleTestExecutionCallback());
    }
}
