/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.simpleTest;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.TestChooser;
import de.rub.nds.tlstest.framework.coffee4j.junit.CombinatorialTlsTestExtension;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.ParameterModelFactory;
import java.lang.reflect.Method;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContextProvider;
import static org.junit.platform.commons.util.AnnotationUtils.isAnnotated;

/**
 *
 */
public class TestChooserExtension implements TestTemplateInvocationContextProvider {

    @Override
    public boolean supportsTestTemplate(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return false;
        }
        
        final Method testMethod = extensionContext.getRequiredTestMethod();
        if (!isAnnotated(testMethod, TestChooser.class)) {
            return false;
        }
        
        DerivationScope scope = new DerivationScope(extensionContext);
        if(ParameterModelFactory.mustUseSimpleModel(TestContext.getInstance(), scope)) {
            return new SimpleTestExtension().supportsTestTemplate(extensionContext);
        } else {
            return new CombinatorialTlsTestExtension().supportsTestTemplate(extensionContext);
        }
    }

    @Override
    public Stream<TestTemplateInvocationContext> provideTestTemplateInvocationContexts(ExtensionContext extensionContext) {
        DerivationScope scope = new DerivationScope(extensionContext);
        if(ParameterModelFactory.mustUseSimpleModel(TestContext.getInstance(), scope)) {
            return new SimpleTestExtension().provideTestTemplateInvocationContexts(extensionContext);
        } else {
            return new CombinatorialTlsTestExtension().provideTestTemplateInvocationContexts(extensionContext);
        }
    }

}
