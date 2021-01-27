package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/**
 * Runs a benign handshake with all default derivations to identify
 * parameter-related bugs.
 */
@Tag("happyflow13")
public class HappyFlow extends Tls13Test {

    @TlsTest(description = "A benign handshake executed with all parameter combinations "
            + " that affect a regular handshake")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @HandshakeCategory(SeverityLevel.HIGH)
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    public void happyFlow(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, c).validateFinal(i -> {
            boolean receivedAlert = WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, i.getWorkflowTrace());
            if (receivedAlert) {
                AlertMessage alert = (AlertMessage) WorkflowTraceUtil.getFirstReceivedMessage(ProtocolMessageType.ALERT, i.getWorkflowTrace());
                LOGGER.error("Received Alert " + AlertDescription.getAlertDescription(alert.getDescription().getValue()) + " for Happy Flow using derivations:\n" + derivationContainer.toString() + "\nWorkflowTrace:\n" + i.getWorkflowTrace().toString());
            }
            Validator.executedAsPlanned(i);
        });
    }
}
