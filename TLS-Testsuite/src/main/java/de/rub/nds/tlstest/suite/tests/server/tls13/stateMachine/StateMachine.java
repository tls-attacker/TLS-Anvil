package de.rub.nds.tlstest.suite.tests.server.tls13.stateMachine;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/**
 *
 */
@Tag("statemachine")
@ServerTest
public class StateMachine extends Tls13Test {
    
    @TlsTest(description = "Send two Client Hello Messages at the beginning of the Handshake")
    @Security(SeverityLevel.CRITICAL)
    public void secondClientHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        de.rub.nds.tlstest.suite.tests.server.tls12.stateMachine.StateMachine.sharedSecondClientHelloTest(config, runner);
    }
    
    @TlsTest(description = "Send a second Client Hello after receiving the server's Handshake messages")
    @Security(SeverityLevel.CRITICAL)
    public void secondClientHelloAfterServerHelloMessages(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        de.rub.nds.tlstest.suite.tests.server.tls12.stateMachine.StateMachine.sharedSecondClientHelloAfterServerHelloTest(config, runner);
    }
    
    @Test
    @TestDescription("An implementation may receive an unencrypted record of type " +
            "change_cipher_spec consisting of the single byte value 0x01 at any " +
            "time after the first ClientHello message has been sent or received")   
    @Security(SeverityLevel.CRITICAL)
    public void beginWithChangeCipherSpec(WorkflowRunner runner) {
        Config config = getConfig();
        de.rub.nds.tlstest.suite.tests.server.tls12.stateMachine.StateMachine.sharedBeginWithChangeCipherSpecTest(config, runner);
    }
    
    @Test
    @TestDescription("Begin the Handshake with Application Data")   
    @Security(SeverityLevel.CRITICAL)
    public void beginWithApplicationData(WorkflowRunner runner) {
        Config config = getConfig();
        de.rub.nds.tlstest.suite.tests.server.tls12.stateMachine.StateMachine.sharedBeginWithApplicationDataTest(config, runner);
    }
    
    @Test
    @TestDescription("Begin the Handshake with a Finished Message")   
    @Security(SeverityLevel.CRITICAL)
    public void beginWithFinished(WorkflowRunner runner) {
        Config config = getConfig();
        de.rub.nds.tlstest.suite.tests.server.tls12.stateMachine.StateMachine.sharedBeginWithFinishedTest(config, runner);
    }
}
