package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.*;

@ServerTest
@RFC(number = 8446, section = "4.1.1 Cryptographic Negotiation")
public class CryptographicNegotiation extends Tls13Test {

    @TlsTest(description = "If the server is unable to negotiate a supported set of parameters " +
            "(i.e., there is no overlap between the client and server parameters), it MUST abort " +
            "the handshake with either a \"handshake_failure\" or \"insufficient_security\" fatal alert (see Section 6).", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void noOverlappingParameters(WorkflowRunner runner) {
        Config config = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        config.setDefaultClientNamedGroups(
                NamedGroup.GREASE_00,
                NamedGroup.GREASE_01,
                NamedGroup.GREASE_02,
                NamedGroup.GREASE_03,
                NamedGroup.GREASE_04
        );

        List<KeyShareStoreEntry> keyshareList = new ArrayList<>();
        NamedGroup group =  context.getConfig().getSiteReport().getSupportedTls13Groups().get(0);
        EllipticCurve curve = CurveFactory.getCurve(group);

        Point publicKey = curve.mult(config.getDefaultClientEcPrivateKey(), curve.getBasePoint());
        byte[] publicKeyBytes = PointFormatter.toRawFormat(publicKey);
        keyshareList.add(new KeyShareStoreEntry(NamedGroup.GREASE_00, publicKeyBytes));

        config.setDefaultClientKeyShareEntries(keyshareList);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = trace.getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }

            AlertDescription description = AlertDescription.getAlertDescription(alert.getDescription().getValue());
            assertTrue(
                    AssertMsgs.UnexpectedAlertDescription,
                    description == AlertDescription.HANDSHAKE_FAILURE || description == AlertDescription.INSUFFICIENT_SECURITY
            );
        });
    }


}
