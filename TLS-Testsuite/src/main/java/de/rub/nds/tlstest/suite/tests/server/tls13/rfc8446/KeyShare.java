/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@ServerTest
@RFC(number = 8446, section = "4.2.8. Key Share")
public class KeyShare extends Tls13Test {

    @TlsTest(description = "Each KeyShareEntry value MUST correspond " +
            "to a group offered in the \"supported_groups\" extension " +
            "and MUST appear in the same order.", securitySeverity = SeverityLevel.MEDIUM, interoperabilitySeverity = SeverityLevel.HIGH)
    public void testOrderOfKeyshareEntries(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;

        Config c = this.getConfig();
        List<NamedGroup> groups = new ArrayList<NamedGroup>(){{
            add(NamedGroup.SECP256R1);
            add(NamedGroup.SECP384R1);
            add(NamedGroup.SECP521R1);
            add(NamedGroup.ECDH_X25519);
            add(NamedGroup.ECDH_X448);
        }};

        List<KeyShareStoreEntry> keyshares = new ArrayList<>();
        for (NamedGroup i : groups) {
            EllipticCurve curve = CurveFactory.getCurve(i);
            Point publicKey = curve.mult(c.getDefaultClientEcPrivateKey(), curve.getBasePoint());
            byte[] publicKeyBytes = PointFormatter.toRawFormat(publicKey);

            keyshares.add(new KeyShareStoreEntry(i, publicKeyBytes));
        }

        c.setDefaultClientKeyShareEntries(keyshares);
        Collections.reverse(groups);
        c.setDefaultClientNamedGroups(groups);


        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            AlertMessage alert = trace.getFirstReceivedMessage(AlertMessage.class);
            ServerHelloMessage shm = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            if (alert != null && shm == null) {
                assertEquals("No fatal alert received", AlertLevel.FATAL.getValue(), alert.getLevel().getValue().byteValue());
                Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
                i.addAdditionalResultInfo("Received alert");
                return;
            }

            assertTrue(AssertMsgs.WorkflowNotExecuted + ", server likely selected the wrong key share",
                    i.getWorkflowTrace().executedAsPlanned());
        });
    }

    @TlsTest(description = "If using (EC)DHE key establishment, servers offer exactly one KeyShareEntry in the ServerHello. " +
            "This value MUST be in the same group as the KeyShareEntry value offered by the client " +
            "that the server has selected for the negotiated key exchange.")
    public void serverOnlyOffersOneKeshare(WorkflowRunner runner) {
        // TODO: Iterate over each TLS 1.3 named group and offer only one key share of a different group in each handshake
        runner.replaceSupportedCiphersuites = true;

        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            KeyShareExtensionMessage keyshare = i.getWorkflowTrace()
                    .getFirstReceivedMessage(ServerHelloMessage.class)
                    .getExtension(KeyShareExtensionMessage.class);
            assertEquals("Server offered more than one keyshare entry", 1, keyshare.getKeyShareList().size());
            assertTrue(c.getDefaultClientNamedGroups().contains(keyshare.getKeyShareList().stream().map(KeyShareEntry::getGroupConfig).collect(Collectors.toList()).get(0)));
        });
    }
}
