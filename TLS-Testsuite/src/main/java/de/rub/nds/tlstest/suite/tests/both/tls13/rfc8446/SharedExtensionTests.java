/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class SharedExtensionTests {
    public static void checkForDuplicateExtensions(HelloMessage helloMessage) {
        assertNotNull(helloMessage, "Hello was not received");
        // There MUST NOT be more than one extension of the
        // same type in a given extension block.
        Set<ExtensionType> uniqueList = new HashSet<>();
        List<ExtensionType> duplicated = new LinkedList<>();
        if (helloMessage.getExtensions() != null) {
            helloMessage
                    .getExtensions()
                    .forEach(
                            extension -> {
                                // TODO: this casting should not be necessary yet the compiler
                                // thinks 'extension' was solely of type object
                                ExtensionMessage extensionMsg = (ExtensionMessage) extension;
                                if (uniqueList.contains(extensionMsg.getExtensionTypeConstant())) {
                                    duplicated.add(extensionMsg.getExtensionTypeConstant());
                                }
                                uniqueList.add(extensionMsg.getExtensionTypeConstant());
                            });
        }
        assertTrue(
                duplicated.isEmpty(),
                "Server included multiple Extensions of the following types: "
                        + duplicated.parallelStream()
                                .map(Enum::name)
                                .collect(Collectors.joining(",")));
    }
}
