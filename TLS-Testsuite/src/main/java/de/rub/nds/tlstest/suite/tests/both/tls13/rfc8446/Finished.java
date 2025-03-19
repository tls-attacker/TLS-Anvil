/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

public class Finished extends Tls13Test {

    @AnvilTest(id = "8446-dZhHUctEjQ")
    @IncludeParameter("PRF_BITMASK")
    public void verifyFinishedMessageCorrect(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(
                new SendAction(new FinishedMessage()), new ReceiveAction(new AlertMessage()));

        byte[] modificationBitmask = parameterCombination.buildBitmask();
        ((FinishedMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.FINISHED))
                .setVerifyData(Modifiable.xor(modificationBitmask, 0));

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage msg = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.DECRYPT_ERROR, msg);
    }
}
