/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 7465, section = "2")
@ServerTest
@Tag("WIP")
public class RC4Ciphersuites extends Tls12Test {

    public boolean isRC4(CipherSuite cipherSuite) {
        return cipherSuite.toString().contains("RC4");
    }
    
    /*
    TODO: isn't this a duplicate?
    
    @TlsTest(description = "TLS servers MUST NOT select an RC4 cipher suite when a TLS client " +
            "sends such a cipher suite in the ClientHello message.", securitySeverity = SeverityLevel.CRITICAL)
    @MethodCondition(method = "supportsRC4")
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
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertArrayEquals(AssertMsgs.UnexpectedCipherSuite, i.getInspectedCipherSuite().getByteValue(), msg.getSelectedCipherSuite().getValue());
        });
    }*/

    @TlsTest(description = "If the TLS client only offers RC4 cipher suites, the TLS server " +
            "MUST terminate the handshake. The TLS server MAY send the " +
            "insufficient_security fatal alert in this case.", securitySeverity = SeverityLevel.CRITICAL)
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods="isRC4")
    public void onlyRC4Suites(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }



}
