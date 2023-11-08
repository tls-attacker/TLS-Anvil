package de.rub.nds.tlstest.suite.tests.both.dtls12.rfc6347;

import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class StreamCipher extends Dtls12Test {

    @Disabled
    public void notRC4(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        // Implemented in class
        // de.rub.nds.tlstest.suite.tests.client.tls12.rfc7465.RC4Ciphersuites.java
    }
}
