/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

@ClientTest
public class Certificate extends Tls13Test {

    @AnvilTest(id = "8446-vN4oMaYkC6")
    public void emptyCertificateMessage(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));
        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                        trace, HandshakeMessageType.CERTIFICATE)
                .setCompleteResultingMessage(
                        Modifiable.explicit(
                                new byte[] {HandshakeMessageType.CERTIFICATE.getValue(), 0, 0, 0}));

        State state = runner.execute(trace, config);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.DECODE_ERROR, alert);
    }

    @AnvilTest(id = "8446-cM4fvnBMce")
    public void emptyCertificateList(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));
        ((CertificateMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                trace, HandshakeMessageType.CERTIFICATE))
                .setCertificatesListBytes(Modifiable.explicit(new byte[] {}));

        State state = runner.execute(trace, config);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.DECODE_ERROR, alert);
    }
}
