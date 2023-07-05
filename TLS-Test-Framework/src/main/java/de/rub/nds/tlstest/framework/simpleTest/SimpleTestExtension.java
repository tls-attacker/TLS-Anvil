/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.simpleTest;

import static org.junit.platform.commons.util.AnnotationUtils.isAnnotated;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.TestChooser;
import de.rub.nds.tlstest.framework.model.ParameterModelFactory;
import java.lang.reflect.Method;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContextProvider;

/**
 * Performs a test where all parameters are static or only one parameter has multiple possible
 * values.
 */
public class SimpleTestExtension implements TestTemplateInvocationContextProvider {

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
        if (!ParameterModelFactory.mustUseSimpleModel(TestContext.getInstance(), scope)) {
            return false;
        }

        return true;
    }

    @Override
    public Stream<TestTemplateInvocationContext> provideTestTemplateInvocationContexts(
            ExtensionContext extensionContext) {
        DerivationScope scope = new DerivationScope(extensionContext);
        List<DerivationParameter> singleVariatingParameter =
                ParameterModelFactory.getSimpleModelVariations(TestContext.getInstance(), scope);
        SimpleTestManagerContainer managerContainer = SimpleTestManagerContainer.getInstance();
        if (singleVariatingParameter != null) {
            managerContainer.addManagerByExtensionContext(
                    extensionContext, singleVariatingParameter.size());
            return singleVariatingParameter.stream()
                    .map(value -> new SimpleTestInvocationContext(value));
        } else {
            managerContainer.addManagerByExtensionContext(extensionContext, 1);
            return Stream.of(new SimpleTestInvocationContext());
        }
    }
}
