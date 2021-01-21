/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7568;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Crypto;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeature;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructure;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayer;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.*;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 7568, section = "3")
@ServerTest
public class DoNotUseSSLVersion30 extends Tls12Test {

    @TlsTest(description = "SSLv3 MUST NOT be used. Negotiation of SSLv3 from any version of TLS "
            + "MUST NOT be permitted. "
            + "Pragmatically, clients MUST NOT send a ClientHello with "
            + "ClientHello.client_version set to {03,00}. Similarly, servers MUST "
            + "NOT send a ServerHello with ServerHello.server_version set to "
            + "{03,00}. Any party receiving a Hello message with the protocol "
            + "version set to {03,00} MUST respond with a \"protocol_version\" alert "
            + "message and close the connection.")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.CRITICAL)
    @DeprecatedFeature(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.CRITICAL)
    @Alert(SeverityLevel.HIGH)
    public void sendClientHelloVersion0300(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x00}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, config).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            byte description = msg.getDescription().getValue();
            try {
                assertEquals(AssertMsgs.NoFatalAlert, AlertDescription.PROTOCOL_VERSION.getValue(), description);
            } catch (AssertionError err) {
                i.addAdditionalResultInfo(String.format("Received invalid alert description. Execpted: %s, got: %s", AlertDescription.PROTOCOL_VERSION, AlertDescription.getAlertDescription(description)));
            }

        });

    }

    public List<DerivationParameter> get03ProtocolVersions() {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        for (byte i : new byte[]{0x00, 0x01, 0x02, 0x04, 0x05, (byte) 0xff}) {
            parameterValues.add(new ProtocolVersionDerivation(new byte[]{0x03, i}));
        }
        return parameterValues;
    }

    @TlsTest(description = "TLS servers MUST accept any value "
            + "{03,XX} (including {03,00}) as the record layer version number for "
            + "ClientHello, but they MUST NOT negotiate SSLv3.")
    @ScopeExtensions(DerivationType.PROTOCOL_VERSION)
    @ExplicitValues(affectedTypes = DerivationType.PROTOCOL_VERSION, methods = "get03ProtocolVersions")
    @ManualConfig(DerivationType.PROTOCOL_VERSION)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.CRITICAL)
    @DeprecatedFeature(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.CRITICAL)
    @Alert(SeverityLevel.HIGH)
    public void sendClientHelloVersion0300WithDifferentVersionInTheRecord(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        byte[] protocolVersionBytes = derivationContainer.getDerivation(ProtocolVersionDerivation.class).getSelectedValue();
        
        Record record = new Record();
        record.setProtocolVersion(Modifiable.explicit(protocolVersionBytes));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);

        SendAction sendAction = new SendAction(clientHelloMessage);
        sendAction.setRecords(record);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, config).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage shm = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, shm);

            assertArrayEquals("Invalid TLS version negotiated", new byte[]{0x03, 0x03}, shm.getProtocolVersion().getValue());
        });
    }

}
