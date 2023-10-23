package de.rub.nds.tlstest.suite.tests.both.dtls12.rfc6347;

import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 6347, section = "4.1.2.2. Null or Standard Stream Cipher")
public class StreamCipher extends Dtls12Test {

    @TlsTest(description = "RC4 MUST NOT be used with DTLS.")
    public void notRC4(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        // Implemented in class
        // de.rub.nds.tlstest.suite.tests.client.tls12.rfc7465.RC4Ciphersuites.java
    }
}