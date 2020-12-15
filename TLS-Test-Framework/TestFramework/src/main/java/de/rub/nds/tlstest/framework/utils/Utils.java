package de.rub.nds.tlstest.framework.utils;

import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Optional;

public class Utils {


    /**
     * @param extensionContext
     * @return Return the extension context that belongs to an {@link de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer}.
     * This is either a {@link org.junit.jupiter.engine.descriptor.TestTemplateExtensionContext} extension context, in case of handshakes are performed,
     * or a {@link org.junit.jupiter.engine.descriptor.MethodExtensionContext} in case no handshakes are performed.
     */
    public static ExtensionContext getTemplateContainerExtensionContext(ExtensionContext extensionContext) {
        if (extensionContextIsTemplateContainer(extensionContext)) {
            return extensionContext;
        } else {
            Optional<ExtensionContext> tmp = extensionContext.getParent();
            while (tmp.isPresent()) {
                if (extensionContextIsTemplateContainer(tmp.get())) {
                    return tmp.get();
                }
                tmp = tmp.get().getParent();
            }
            return extensionContext;
        }

    }

    public static boolean extensionContextIsTemplateContainer(ExtensionContext extensionContext) {
        try {
            // Pretty ugly, but the class is not public and there are no other ways
            // to find out, if the extension context belongs to an invocation context (aka handshake)
            // or to the test template method, which is the container.
            // Be careful by updating JUnit :D
            Class<?> clazz = Class.forName("org.junit.jupiter.engine.descriptor.TestTemplateExtensionContext");
            return clazz.isAssignableFrom(extensionContext.getClass());
        } catch (Exception E) {
            throw new RuntimeException(E);
        }
    }
}
