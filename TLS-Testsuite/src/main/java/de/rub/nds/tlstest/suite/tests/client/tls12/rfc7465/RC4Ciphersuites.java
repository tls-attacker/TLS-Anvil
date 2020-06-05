package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7465;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RFC(number = 7465, section = "2")
@ClientTest
public class RC4Ciphersuites extends Tls12Test {

    public ConditionEvaluationResult supportsRC4(ExtensionContext context) {
        List<CipherSuite> supported = new ArrayList<>(this.context.getConfig().getSiteReport().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));

        return supported.size() == 0 ? ConditionEvaluationResult.disabled("No RC4 Ciphersuite supported") : ConditionEvaluationResult.enabled("");
    }

    @TlsTest(description = "TLS clients MUST NOT include RC4 cipher suites in the ClientHello message.", securitySeverity = SeverityLevel.CRITICAL)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void offersRC4Ciphersuites(WorkflowRunner runner) {
        List<CipherSuite> supported = new ArrayList<>(this.context.getConfig().getSiteReport().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));
        if (supported.size() > 0) {
            throw new AssertionError("Client supports RC4 Ciphersuites");
        }
    }

    @TlsTest(description = "TLS servers MUST NOT select an RC4 cipher suite when a TLS client sends such " +
            "a cipher suite in the ClientHello message.", securitySeverity = SeverityLevel.CRITICAL)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @MethodCondition(clazz = RC4Ciphersuites.class, method = "supportsRC4")
    public void selectRC4CipherSuite(WorkflowRunner runner) {
        List<CipherSuite> supported = new ArrayList<>(this.context.getConfig().getSiteReport().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));

        AnnotatedStateContainer container = new AnnotatedStateContainer();
        for (CipherSuite i : supported) {
            Config config = context.getConfig().createConfig();
            config.setDefaultServerSupportedCiphersuites(i);
            config.setDefaultSelectedCipherSuite(i);

            WorkflowTrace trace = new WorkflowTrace();
            trace.addTlsActions(
                    new ReceiveAction(new ClientHelloMessage(config)),
                    new SendAction(
                            new ServerHelloMessage(config),
                            new CertificateMessage(config)
                    ),
                    new SendDynamicServerKeyExchangeAction(),
                    new SendAction(
                            new ServerHelloDoneMessage(config)
                    ),
                    new ReceiveAction(new AlertMessage())
            );

            container.addAll(runner.prepare(trace, config));
        }

        runner.execute(container).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.smartExecutedAsPlanned());

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) {
                i.addAdditionalResultInfo("Timeout");
                return;
            }

            assertEquals(AssertMsgs.NoFatalAlert, AlertLevel.FATAL.getValue(), msg.getLevel().getValue().byteValue());
        });

    }


}
