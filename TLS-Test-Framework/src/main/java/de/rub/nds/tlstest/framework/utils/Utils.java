/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.utils;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import java.io.File;
import java.lang.reflect.Method;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Optional;
import java.util.TimeZone;
import org.junit.jupiter.api.extension.ExtensionContext;

public class Utils {

    /**
     * @param extensionContext
     * @return Return the extension context that belongs to an {@link
     *     de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer}. This is either a {@link
     *     org.junit.jupiter.engine.descriptor.TestTemplateExtensionContext} extension context, in
     *     case of handshakes are performed, or a {@link
     *     org.junit.jupiter.engine.descriptor.MethodExtensionContext} in case no handshakes are
     *     performed.
     */
    public static ExtensionContext getTemplateContainerExtensionContext(
            ExtensionContext extensionContext) {
        if (!extensionContextIsBasedOnCombinatorialTesting(extensionContext)) {
            return extensionContext;
        } else {
            Optional<ExtensionContext> tmp = extensionContext.getParent();
            while (tmp.isPresent()) {
                if (extensionContextIsBasedOnCombinatorialTesting(tmp.get())) {
                    return tmp.get();
                }
                tmp = tmp.get().getParent();
            }
            return extensionContext;
        }
    }

    public static boolean extensionContextIsBasedOnCombinatorialTesting(
            ExtensionContext extensionContext) {
        Optional<Method> testMethod = extensionContext.getTestMethod();
        // this will also yield false for all disabled tests
        return testMethod.isPresent() && testMethod.get().isAnnotationPresent(AnvilTest.class);
    }

    public static String DateToISO8601UTC(Date date) {
        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH-mm-ss'Z'");
        df.setTimeZone(tz);
        return df.format(date);
    }

    public static void createEmptyFile(String path) {
        File f = new File(path);
        f.getParentFile().mkdirs();
        try {
            f.createNewFile();
        } catch (Exception ignored) {
        }
    }
}
