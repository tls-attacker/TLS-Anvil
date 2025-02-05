/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc6066;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
public class MaximumFragmentLength extends Tls12Test {

    public ConditionEvaluationResult targetCanBeTested() {
        ServerFeatureExtractionResult extractionResult =
                (ServerFeatureExtractionResult) context.getFeatureExtractionResult();

        if (extractionResult.getNegotiableExtensions() != null
                && extractionResult
                        .getNegotiableExtensions()
                        .contains(ExtensionType.MAX_FRAGMENT_LENGTH)) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled("Target does not support the Extension");
    }

    @AnvilTest(id = "6066-39keM8ZKdL")
    @MethodCondition(method = "targetCanBeTested")
    public void invalidMaximumFragmentLength(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        c.setAddMaxFragmentLengthExtension(true);
        ClientHelloMessage chm = new ClientHelloMessage(c);

        chm.getExtension(MaxFragmentLengthExtensionMessage.class)
                .setMaxFragmentLength(Modifiable.explicit(new byte[] {10}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new SendAction(chm), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);

        WorkflowTrace trace = state.getWorkflowTrace();
        AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);

        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
    }

    @AnvilTest(id = "6066-UYvTvBM1mm")
    @MethodCondition(method = "targetCanBeTested")
    @Tag("new")
    public void respectsNegotiatedMaxFragmentLength(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddMaxFragmentLengthExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
        ServerHelloMessage serverHello =
                state.getWorkflowTrace().getLastReceivedMessage(ServerHelloMessage.class);
        assertTrue(
                "MaxFragmentLength has not been negotiated by the server",
                serverHello.containsExtension(ExtensionType.MAX_FRAGMENT_LENGTH));
        MaxFragmentLength selectedMaxFragment =
                MaxFragmentLength.getMaxFragmentLength(
                        serverHello
                                .getExtension(MaxFragmentLengthExtensionMessage.class)
                                .getMaxFragmentLength()
                                .getValue()[0]);
        int maxPlaintextFragmentSize = selectedMaxFragment.getReceiveLimit();

        WorkflowTrace trace = state.getWorkflowTrace();
        for (int j = 1; j < WorkflowTraceResultUtil.getAllReceivedRecords(trace).size(); j++) {
            Record record = WorkflowTraceResultUtil.getAllReceivedRecords(trace).get(j);
            assertTrue(
                    "Plaintextbytes of record exceeded limit",
                    record.getCleanProtocolMessageBytes().getValue().length
                            <= maxPlaintextFragmentSize);
        }
    }
}
