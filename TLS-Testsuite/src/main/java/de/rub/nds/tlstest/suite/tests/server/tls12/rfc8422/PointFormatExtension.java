/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc8422;

import static org.junit.Assert.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class PointFormatExtension extends Tls12Test {

    private static final Logger LOGGER = LogManager.getLogger();

    @AnvilTest
    @KeyExchange(supported = KeyExchangeType.ECDH)
    public void serverAdvertisesOnlyUncompressedPointFormat(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.executedAsPlanned(i);

                            ServerHelloMessage message =
                                    trace.getFirstReceivedMessage(ServerHelloMessage.class);
                            assertNotNull(AssertMsgs.SERVER_HELLO_NOT_RECEIVED, message);

                            ECPointFormatExtensionMessage ext =
                                    message.getExtension(ECPointFormatExtensionMessage.class);

                            if (ext != null) {
                                byte[] points = ext.getPointFormats().getValue();
                                boolean containsZero = false;
                                boolean containsOther = false;
                                for (byte b : points) {
                                    if (b == ECPointFormat.UNCOMPRESSED.getValue()) {
                                        containsZero = true;
                                    } else {
                                        containsOther = true;
                                    }
                                }

                                assertTrue(
                                        "ECPointFormatExtension does not contain uncompressed format",
                                        containsZero);
                                if (choseRfc8422Curve(i.getState().getTlsContext())) {
                                    assertFalse(
                                            "ECPointFormatExtension contains compressed / invalid format",
                                            containsOther);
                                }
                            }
                        });
    }

    @AnvilTest
    @KeyExchange(supported = KeyExchangeType.ECDH)
    public void invalidPointFormat(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new SendAction(chm), new ReceiveAction(new AlertMessage()));

        chm.getExtension(ECPointFormatExtensionMessage.class)
                .setPointFormats(Modifiable.explicit(new byte[] {(byte) 33}));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    @AnvilTest
    @KeyExchange(supported = KeyExchangeType.ECDH)
    public void deprecatedFormat(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        LinkedList<ECPointFormat> formats = new LinkedList<>();
        formats.add(ECPointFormat.ANSIX962_COMPRESSED_CHAR2);
        formats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        c.setDefaultClientSupportedPointFormats(formats);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    // See 5.1.1.  Supported Elliptic Curves Extension
    private boolean choseRfc8422Curve(TlsContext context) {
        if (context.getSelectedGroup() == NamedGroup.SECP256R1
                || context.getSelectedGroup() == NamedGroup.SECP384R1
                || context.getSelectedGroup() == NamedGroup.SECP521R1
                || context.getSelectedGroup() == NamedGroup.ECDH_X25519
                || context.getSelectedGroup() == NamedGroup.ECDH_X448) {
            return true;
        }
        return false;
    }
}
