/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc6066;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

public class MaxFragmentLengthExtension extends Tls12Test {

    public ConditionEvaluationResult supportsMaxFragmentLength() {
        FeatureExtractionResult extractionResult = context.getFeatureExtractionResult();
        if ((context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER
                        && ((ServerFeatureExtractionResult) extractionResult)
                                .getNegotiableExtensions()
                                .contains(ExtensionType.MAX_FRAGMENT_LENGTH))
                || (context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT
                        && ((ClientFeatureExtractionResult) extractionResult)
                                .getAdvertisedExtensions()
                                .contains(ExtensionType.MAX_FRAGMENT_LENGTH))) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled(
                "Client does not support maximum fragment length");
    }

    @AnvilTest(id = "6066-XH6ZKSteMh")
    @ExcludeParameter("MAX_FRAGMENT_LENGTH")
    @MethodCondition(method = "supportsMaxFragmentLength")
    @Tag("new")
    public void enforcesRecordLimit(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setDefaultMaxFragmentLength(MaxFragmentLength.TWO_9);
        config.setAddMaxFragmentLengthExtension(true);
        MaxFragmentLength maxLength = getNegotiatedMaxFragmentLength(config);
        ApplicationMessage overflowingAppData = new ApplicationMessage();
        overflowingAppData.setData(
                Modifiable.explicit(new byte[maxLength.getReceiveLimit() + 256 + 32]));

        SendAction sendOverflowingRecord = new SendAction(overflowingAppData);

        // use a record that ignores the extension's limitations
        Record fullRecord = new Record();
        fullRecord.setMaxRecordLengthConfig(16384);
        sendOverflowingRecord.setConfiguredRecords(List.of(fullRecord));
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsAction(sendOverflowingRecord);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.RECORD_OVERFLOW);
    }

    private MaxFragmentLength getNegotiatedMaxFragmentLength(Config config) {
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            return config.getDefaultMaxFragmentLength();
        } else {
            return MaxFragmentLength.getMaxFragmentLength(
                    context.getReceivedClientHelloMessage()
                            .getExtension(MaxFragmentLengthExtensionMessage.class)
                            .getMaxFragmentLength()
                            .getValue()[0]);
        }
    }
}
