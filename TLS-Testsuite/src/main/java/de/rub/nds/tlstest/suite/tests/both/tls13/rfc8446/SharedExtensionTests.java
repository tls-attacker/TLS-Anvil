package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class SharedExtensionTests {
    public static void checkForDuplicateExtensions(HelloMessage helloMessage) {
        assertNotNull("Hello was not received", helloMessage);
        //There MUST NOT be more than one extension of the
        //same type in a given extension block.   
        Set<ExtensionType> uniqueList = new HashSet<>();
        List<ExtensionType> duplicated = new LinkedList<>();
        helloMessage.getExtensions().forEach(extension -> {
            if(uniqueList.contains(extension.getExtensionTypeConstant())) {
                duplicated.add(extension.getExtensionTypeConstant());
            }
            uniqueList.add(extension.getExtensionTypeConstant());
        });
        assertTrue("Server included multiple Extensions of the following types: " + duplicated.parallelStream().map(Enum::name).collect(Collectors.joining(",")), duplicated.isEmpty());
    }
}
