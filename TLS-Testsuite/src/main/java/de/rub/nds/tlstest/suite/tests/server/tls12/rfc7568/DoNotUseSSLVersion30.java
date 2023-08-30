/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7568;

import static org.junit.Assert.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.ExplicitValues;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.ManualConfig;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.model.AnvilTestTemplate;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
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
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 7568, section = "3. Do Not Use SSL Version 3.0")
@ServerTest
public class DoNotUseSSLVersion30 extends Tls12Test {

    @AnvilTest(
            description =
                    "SSLv3 MUST NOT be used. Negotiation of SSLv3 from any version of TLS "
                            + "MUST NOT be permitted. [...]"
                            + "Pragmatically, clients MUST NOT send a ClientHello with "
                            + "ClientHello.client_version set to {03,00}. Similarly, servers MUST "
                            + "NOT send a ServerHello with ServerHello.server_version set to "
                            + "{03,00}. Any party receiving a Hello message with the protocol "
                            + "version set to {03,00} MUST respond with a \"protocol_version\" alert "
                            + "message and close the connection.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @DeprecatedFeatureCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void sendClientHelloVersion0300(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x00}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage), new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.receivedFatalAlert(i);
                            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.PROTOCOL_VERSION, msg);
                        });
    }

    public List<DerivationParameter<Config, byte[]>> get03ProtocolVersions(
            AnvilTestTemplate scope) {
        List<DerivationParameter<Config, byte[]>> parameterValues = new LinkedList<>();
        for (byte i : new byte[] {0x00, 0x01, 0x02, 0x04, 0x05, (byte) 0xff}) {
            parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, i}));
        }
        return parameterValues;
    }

    @AnvilTest(
            description =
                    "TLS servers MUST accept any value "
                            + "{03,XX} (including {03,00}) as the record layer version number for "
                            + "ClientHello, but they MUST NOT negotiate SSLv3.")
    @IncludeParameter("PROTOCOL_VERSION")
    // we can't retain the version across all records if we don't know how
    // many are required
    @ExcludeParameter("RECORD_LENGTH")
    @ExplicitValues(affectedIdentifiers = "PROTOCOL_VERSION", methods = "get03ProtocolVersions")
    @ManualConfig(identifiers = "PROTOCOL_VERSION")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @DeprecatedFeatureCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.HIGH)
    public void sendClientHelloVersion0300DifferentRecordVersion(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        byte[] protocolVersionBytes =
                parameterCombination
                        .getParameter(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        Record record = new Record();
        record.setProtocolVersion(Modifiable.explicit(protocolVersionBytes));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x00}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage), new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.receivedFatalAlert(i);
                            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.PROTOCOL_VERSION, msg);
                        });
    }

    @AnvilTest(
            description =
                    "TLS servers MUST accept any value "
                            + "{03,XX} (including {03,00}) as the record layer version number for "
                            + "ClientHello, but they MUST NOT negotiate SSLv3.")
    @IncludeParameter("PROTOCOL_VERSION")
    // we can't retain the version across all records if we don't know how
    // many are required
    @ExcludeParameter("RECORD_LENGTH")
    @ExplicitValues(affectedIdentifiers = "PROTOCOL_VERSION", methods = "get03ProtocolVersions")
    @ManualConfig(identifiers = "PROTOCOL_VERSION")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @DeprecatedFeatureCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.HIGH)
    public void sendClientHelloVersion0300RecordVersion(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        byte[] protocolVersionBytes =
                parameterCombination
                        .getParameter(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        Record record = new Record();
        record.setProtocolVersion(Modifiable.explicit(protocolVersionBytes));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);

        SendAction sendAction = new SendAction(clientHelloMessage);
        sendAction.setRecords(record);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendAction, new ReceiveTillAction(new ServerHelloDoneMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.executedAsPlanned(i);

                            ServerHelloMessage shm =
                                    trace.getFirstReceivedMessage(ServerHelloMessage.class);
                            assertNotNull(AssertMsgs.SERVER_HELLO_NOT_RECEIVED, shm);

                            assertArrayEquals(
                                    "Invalid TLS version negotiated",
                                    new byte[] {0x03, 0x03},
                                    shm.getProtocolVersion().getValue());
                        });
    }
}
