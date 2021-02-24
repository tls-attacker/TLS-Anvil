/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc8422;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertFalse;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;

@ServerTest
public class PointFormatExtension extends Tls12Test {

    private static final Logger LOGGER = LogManager.getLogger();

    @RFC(number = 8422, section = "5.2. Server Hello Extensions")
    @TlsTest(description = "Implementations of this document MUST support the "
            + "uncompressed format for all of their supported curves and MUST NOT "
            + "support other formats for curves defined in this specification.  For "
            + "backwards compatibility purposes, the point format list extension MAY "
            + "still be included and contain exactly one value: the uncompressed "
            + "point format (0).")
    @KeyExchange(supported = KeyExchangeType.ECDH)
    @InteroperabilityCategory(SeverityLevel.HIGH) 
    @HandshakeCategory(SeverityLevel.MEDIUM) 
    @ComplianceCategory(SeverityLevel.HIGH)
    @DeprecatedFeatureCategory(SeverityLevel.MEDIUM)
    public void serverAdvertisesOnlyUncompressedPointFormat(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage message = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, message);

            ECPointFormatExtensionMessage ext = message.getExtension(ECPointFormatExtensionMessage.class);

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

                assertTrue("ECPointFormatExtension does not contain uncompressed format", containsZero);
                if (choseRfc8422Curve(i.getState().getTlsContext())) {
                    assertFalse("ECPointFormatExtension contains compressed / invalid format", containsOther);
                }
            }
        });
    }

    @RFC(number = 8422, section = "5.1. Client Hello Extensions")
    @TlsTest(description = "If the client sends the extension and the extension does not contain "
            + "the uncompressed point format, and the client has used the Supported "
            + "Groups extension to indicate support for any of the curves defined in "
            + "this specification, then the server MUST abort the handshake and "
            + "return an illegal_parameter alert.")
    @KeyExchange(supported = KeyExchangeType.ECDH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void invalidPointFormat(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm),
                new ReceiveAction(new AlertMessage(c))
        );

        chm.getExtension(ECPointFormatExtensionMessage.class)
                .setPointFormats(Modifiable.explicit(new byte[]{(byte) 33}));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    @RFC(number = 8422, section = "5.1. Client Hello Extensions")
    @TlsTest(description = "If the client sends the extension and the extension does not contain "
            + "the uncompressed point format, and the client has used the Supported "
            + "Groups extension to indicate support for any of the curves defined in "
            + "this specification, then the server MUST abort the handshake and "
            + "return an illegal_parameter alert.")
    @KeyExchange(supported = KeyExchangeType.ECDH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @DeprecatedFeatureCategory(SeverityLevel.MEDIUM)
    public void deprecatedFormat(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        LinkedList<ECPointFormat> formats = new LinkedList<>();
        formats.add(ECPointFormat.ANSIX962_COMPRESSED_CHAR2);
        formats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        c.setDefaultClientSupportedPointFormats(formats);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    //See 5.1.1.  Supported Elliptic Curves Extension
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
