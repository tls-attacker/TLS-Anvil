package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7465;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.ArrayList;
import java.util.List;

@RFC(number = 7465, section = "2")
@ClientTest
public class RC4Ciphersuites extends Tls12Test {

    public ConditionEvaluationResult supportsRC4(ExtensionContext context) {
        List<CipherSuite> supported = new ArrayList<>(this.context.getConfig().getSiteReport().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));

        return supported.size() == 0 ? ConditionEvaluationResult.disabled("No RC4 Ciphersuite supported") : ConditionEvaluationResult.enabled("");
    }

    @TlsTest(description = "TLS clients MUST NOT include RC4 cipher suites in the ClientHello message.", securitySeverity = SeverityLevel.CRITICAL)
    public void offersRC4Ciphersuites(WorkflowRunner runner) {
        List<CipherSuite> supported = new ArrayList<>(this.context.getConfig().getSiteReport().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));
        if (supported.size() > 0) {
            throw new AssertionError("Client supports RC4 Ciphersuites");
        }
    }

    @TlsTest(description = "TLS servers MUST NOT select an RC4 cipher suite when a TLS client sends such " +
            "a cipher suite in the ClientHello message.", securitySeverity = SeverityLevel.CRITICAL)
    @MethodCondition(clazz = RC4Ciphersuites.class, method = "supportsRC4")
    public void selectRC4CipherSuite(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        runner.respectConfigSupportedCiphersuites = true;

        List<CipherSuite> supported = new ArrayList<>(this.context.getConfig().getSiteReport().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));

        Config config = this.getConfig();
        config.setDefaultServerSupportedCiphersuites(supported);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
}
