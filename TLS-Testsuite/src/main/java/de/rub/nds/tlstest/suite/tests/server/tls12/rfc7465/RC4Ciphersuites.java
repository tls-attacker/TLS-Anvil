package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7465;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

@RFC(number = 7465, section = "2")
@ServerTest
public class RC4Ciphersuites extends Tls12Test {

    public ConditionEvaluationResult supportsRC4(ExtensionContext context) {
        List<CipherSuite> supported = new ArrayList<>(this.context.getConfig().getSiteReport().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));

        return supported.size() == 0 ? ConditionEvaluationResult.disabled("No RC4 Ciphersuite supported") : ConditionEvaluationResult.enabled("");
    }

    @TlsTest(description = "TLS servers MUST NOT select an RC4 cipher suite when a TLS client" +
            " sends such a cipher suite in the ClientHello message.", securitySeverity = SeverityLevel.CRITICAL)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @MethodCondition(clazz = RC4Ciphersuites.class, method = "supportsRC4")
    public void offerRC4AndOtherCiphers(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.appendEachSupportedCiphersuiteToClientSupported = true;

        List<CipherSuite> implemented = CipherSuite.getImplemented();
        implemented.removeIf(i -> !i.toString().contains("RC4"));

        c.setDefaultClientSupportedCiphersuites(implemented);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertArrayEquals(AssertMsgs.UnexpectedCipherSuite, i.getInspectedCipherSuite().getByteValue(), msg.getSelectedCipherSuite().getValue());
        });
    }

    @TlsTest(description = "If the TLS client only offers RC4 cipher suites, the TLS server" +
            " MUST terminate the handshake.  The TLS server MAY send the" +
            " insufficient_security fatal alert in this case.", securitySeverity = SeverityLevel.CRITICAL)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @MethodCondition(clazz = RC4Ciphersuites.class, method = "supportsRC4")
    public void onlyRC4Suites(WorkflowRunner runner) {
        Config c = this.getConfig();

        List<CipherSuite> implemented = CipherSuite.getImplemented();
        implemented.removeIf(i -> !i.toString().contains("RC4"));

        c.setDefaultClientSupportedCiphersuites(implemented);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }



}
