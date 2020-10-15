/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;

@ClientTest
@RFC(number = 8446, section = "4.2.8. Key Share")
public class KeyShare extends Tls13Test {

    @TlsTest(description = "Each KeyShareEntry value MUST correspond " +
            "to a group offered in the \"supported_groups\" extension " +
            "and MUST appear in the same order.", securitySeverity = SeverityLevel.MEDIUM)
    public void testOrderOfKeyshareEntries() {
        ClientHelloMessage chm = context.getReceivedClientHelloMessage();
        EllipticCurvesExtensionMessage groups = chm.getExtension(EllipticCurvesExtensionMessage.class);
        KeyShareExtensionMessage keyshare = chm.getExtension(KeyShareExtensionMessage.class);

        try {
            List<KeyShareEntry> keyshares = keyshare.getKeyShareList();
            List<NamedGroup> namedGroups = NamedGroup.namedGroupsFromByteArray(groups.getSupportedGroups().getValue());

            int index = -1;
            List<NamedGroup> checkedGroups = new ArrayList<>();
            for (KeyShareEntry i : keyshares) {
                int tmpIndex = namedGroups.indexOf(i.getGroupConfig());
                assertTrue("Keyshare group not part of supported groups", tmpIndex > -1);
                assertTrue("Keyshares are in the wrong order", tmpIndex > index);
                assertFalse("Two Keyshare entries for the same group found", checkedGroups.contains(i.getGroupConfig()));

                index = tmpIndex;
                checkedGroups.add(i.getGroupConfig());
            }
        } catch (Exception e) {
            throw new AssertionError("Exception occurred", e);
        }
    }

    @TlsTest(description = "If using (EC)DHE key establishment, servers offer exactly one KeyShareEntry in the ServerHello. " +
            "This value MUST be in the same group as the KeyShareEntry value offered by the client " +
            "that the server has selected for the negotiated key exchange.")
    public void selectInvalidKeyshare(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();

        ClientHelloMessage chm = context.getReceivedClientHelloMessage();
        List<NamedGroup> groups = context.getSiteReport().getSupportedNamedGroups();
        KeyShareExtensionMessage keyshare = chm.getExtension(KeyShareExtensionMessage.class);

        for (KeyShareEntry i : keyshare.getKeyShareList()) {
            groups.remove(i.getGroupConfig());
        }

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        if (groups.size() == 0) {
            runner.setStateModifier(i -> {
                KeyShareExtensionMessage keyShareExt = i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class).getExtension(KeyShareExtensionMessage.class);
                keyShareExt.setKeyShareListBytes(Modifiable.explicit(new byte[]{0x50, 0x50, 0, 1, 1}));
                return null;
            });
        }
        else {
            EllipticCurve curve = CurveFactory.getCurve(groups.get(0));
            Point pubKey = curve.mult(c.getDefaultServerEcPrivateKey(), curve.getBasePoint());
            byte[] key = PointFormatter.toRawFormat(pubKey);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            try {
                stream.write(groups.get(0).getValue());
                stream.write(ArrayConverter.intToBytes(key.length, 2));
                stream.write(key);
            } catch (Exception e) {
                throw new RuntimeException("ByteArrayOutputStream is broken");
            }

            runner.setStateModifier(i -> {
                KeyShareExtensionMessage keyShareExt = i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class).getExtension(KeyShareExtensionMessage.class);
                keyShareExt.setKeyShareListBytes(Modifiable.explicit(stream.toByteArray()));
                return null;
            });
        }

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "RFC 8446 (TLS 1.3) and RFC 8422 deprecated most older elliptic curves")
    public void offeredDeprecatedGroups() {
        ClientHelloMessage chm = context.getReceivedClientHelloMessage();
        boolean foundDeprecated = false;
        for(KeyShareEntry ks : chm.getExtension(KeyShareExtensionMessage.class).getKeyShareList()) {
            if(ks.getGroupConfig() != null && !ks.getGroupConfig().isTls13()) {
                foundDeprecated = true;
                break;
            }
        }
        assertFalse("Deprecated or invalid group used for key share", foundDeprecated);
    }
}
