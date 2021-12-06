/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.BasicDerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.InvalidCCSContentDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertEquals;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;


@RFC(number = 5264, section = "7.1 Change Cipher Spec Protocol")
public class ChangeCipherSpecProtocol extends Tls12Test {

    //don't split ccs into multiple records
    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
	return lengthCandidate >= 2;
    }
    
    @TlsTest(description = "The message consists of a single byte of value 1.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @DynamicValueConstraints(affectedTypes = "BasicDerivationType.RECORD_LENGTH", methods = "recordLengthAllowsModification")
    @ScopeExtensions("BasicDerivationType.INVALID_CCS_CONTENT")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void ccsContentTest(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        byte[] content = derivationContainer.getDerivation(InvalidCCSContentDerivation.class).getSelectedValue();
        ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(c);
        changeCipherSpecMessage.setCcsProtocolType(Modifiable.explicit(content));

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsActions(
                new SendAction(changeCipherSpecMessage),
                new SendAction(ActionOption.MAY_FAIL, new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            ChangeCipherSpecMessage msg = trace.getFirstReceivedMessage(ChangeCipherSpecMessage.class);
            if (msg != null) {
                assertEquals(1, msg.getCcsProtocolType().getValue().length);
                assertEquals(1, msg.getCcsProtocolType().getValue()[0]);
            }
        });
    }
}
