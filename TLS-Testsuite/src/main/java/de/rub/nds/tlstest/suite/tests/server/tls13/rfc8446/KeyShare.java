/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.Assert.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.ec.*;
import de.rub.nds.tlsattacker.core.crypto.ffdh.FFDHEGroup;
import de.rub.nds.tlsattacker.core.crypto.ffdh.GroupFactory;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.InvalidCurvePoint;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.TwistedCurvePoint;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.keyexchange.dhe.ShareOutOfBoundsDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class KeyShare extends Tls13Test {

    @AnvilTest(id = "8446-9hMnjrCbMV")
    @ExcludeParameter("NAMED_GROUP")
    /*
        Servers MAY check for violations of these rules and abort the
        handshake with an "illegal_parameter" alert if one is violated.
    */
    @EnforcedSenderRestriction
    public void testOrderOfKeyshareEntries(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        List<NamedGroup> groups =
                new ArrayList<NamedGroup>() {
                    {
                        add(NamedGroup.SECP256R1);
                        add(NamedGroup.SECP384R1);
                        add(NamedGroup.SECP521R1);
                        add(NamedGroup.ECDH_X25519);
                        add(NamedGroup.ECDH_X448);
                    }
                };

        c.setDefaultClientKeyShareNamedGroups(new ArrayList<>(groups));
        Collections.reverse(groups);
        c.setDefaultClientNamedGroups(groups);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            AlertMessage alert = trace.getFirstReceivedMessage(AlertMessage.class);
                            ServerHelloMessage shm =
                                    trace.getFirstReceivedMessage(ServerHelloMessage.class);
                            if (alert != null && shm == null) {
                                assertEquals(
                                        "No fatal alert received",
                                        AlertLevel.FATAL.getValue(),
                                        alert.getLevel().getValue().byteValue());
                                Validator.testAlertDescription(
                                        i, AlertDescription.ILLEGAL_PARAMETER, alert);
                                i.addAdditionalResultInfo("Received alert");
                                return;
                            }

                            assertTrue(
                                    AssertMsgs.WORKFLOW_NOT_EXECUTED
                                            + ", server likely selected the wrong key share",
                                    i.getWorkflowTrace().executedAsPlanned());
                        });
    }

    @AnvilTest(id = "8446-R2rb1WZoQo")
    public void serverOnlyOffersOneKeyshare(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        List<NamedGroup> supportedTls13 = context.getFeatureExtractionResult().getTls13Groups();

        // place selected group at the top to avoid (optional) HRR
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        supportedTls13.remove(selectedGroup);
        supportedTls13.add(0, selectedGroup);

        c.setDefaultClientNamedGroups(supportedTls13);
        performOneKeyshareTest(c, runner);
    }

    @AnvilTest(id = "8446-TKn1mNn5mY")
    @ExcludeParameter("NAMED_GROUP")
    public void serverOnlyOffersOneKeyshareAllGroupsAtOnce(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        List<NamedGroup> supportedTls13 = context.getFeatureExtractionResult().getTls13Groups();
        c.setDefaultClientKeyShareNamedGroups(supportedTls13);
        c.setDefaultClientNamedGroups(supportedTls13);
        performOneKeyshareTest(c, runner);
    }

    public void performOneKeyshareTest(Config c, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            ServerHelloMessage serverHello =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(ServerHelloMessage.class);
                            assertTrue("No ServerHello has been received", serverHello != null);
                            KeyShareExtensionMessage keyshare =
                                    serverHello.getExtension(KeyShareExtensionMessage.class);
                            if (serverHello.isTls13HelloRetryRequest()) {
                                i.addAdditionalResultInfo("Server enforced own preferred group");
                                assertTrue(
                                        "Server requested an unproposed group in HelloRetryRequest",
                                        c.getDefaultClientNamedGroups()
                                                .contains(
                                                        keyshare.getKeyShareList().stream()
                                                                .map(KeyShareEntry::getGroupConfig)
                                                                .collect(Collectors.toList())
                                                                .get(0)));
                            } else {
                                Validator.executedAsPlanned(i);
                                assertTrue(
                                        "Server selected group for which no Key Share was sent outside of HelloRetryRequest",
                                        c.getDefaultClientKeyShareNamedGroups()
                                                .contains(
                                                        keyshare.getKeyShareList().stream()
                                                                .map(KeyShareEntry::getGroupConfig)
                                                                .collect(Collectors.toList())
                                                                .get(0)));
                            }
                            assertEquals(
                                    "Server offered more than one keyshare entry",
                                    1,
                                    keyshare.getKeyShareList().size());
                        });
    }

    public List<DerivationParameter<Config, NamedGroup>> getLegacyGroups(DerivationScope scope) {
        List<DerivationParameter<Config, NamedGroup>> parameterValues = new LinkedList<>();
        List<NamedGroup> groups = NamedGroup.getImplemented();
        groups.removeIf(i -> i.isTls13());
        groups.forEach(i -> parameterValues.add(new NamedGroupDerivation(i)));
        return parameterValues;
    }

    @AnvilTest(id = "8446-KdkvUJX3HK")
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getLegacyGroups")
    public void serverAcceptsDeprecatedGroups(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        List<NamedGroup> groups = NamedGroup.getImplemented();
        groups.removeIf(i -> i.isTls13());
        performDeprecatedGroupsTest(c, runner);
    }

    @AnvilTest(id = "8446-1vps8J91dU")
    @ExcludeParameter("NAMED_GROUP")
    public void serverAcceptsDeprecatedGroupsAllAtOnce(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        List<NamedGroup> groups = NamedGroup.getImplemented();
        groups.removeIf(i -> i.isTls13());
        c.setDefaultClientNamedGroups(groups);
        c.setDefaultClientKeyShareNamedGroups(groups);

        performDeprecatedGroupsTest(c, runner);
    }

    public void performDeprecatedGroupsTest(Config c, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        List<NamedGroup> groups = c.getDefaultClientKeyShareNamedGroups();

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            if (WorkflowTraceUtil.didReceiveMessage(
                                            HandshakeMessageType.SERVER_HELLO, trace)
                                    && trace.getFirstReceivedMessage(ServerHelloMessage.class)
                                            .containsExtension(ExtensionType.KEY_SHARE)) {
                                KeyShareExtensionMessage ksExt =
                                        trace.getFirstReceivedMessage(ServerHelloMessage.class)
                                                .getExtension(KeyShareExtensionMessage.class);
                                assertFalse(
                                        "Server accepted a deprecated group",
                                        groups.contains(
                                                ksExt.getKeyShareList().stream()
                                                        .map(KeyShareEntry::getGroupConfig)
                                                        .collect(Collectors.toList())
                                                        .get(0)));
                                // other groups may not be used - even in HelloRetryRequest
                                assertTrue(
                                        "Server selected an unproposed group",
                                        groups.contains(
                                                ksExt.getKeyShareList().stream()
                                                        .map(KeyShareEntry::getGroupConfig)
                                                        .collect(Collectors.toList())
                                                        .get(0)));
                            }
                        });
    }

    @AnvilTest(id = "8446-tCzswEB5Ua")
    public void includeUnknownGroup(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        byte[] undefinedGroup = new byte[] {(byte) 123, 124};
        byte[] dummyLength = new byte[] {(byte) 0, 56};
        byte[] dummyPublicKey = new byte[56];

        byte[] completeEntry =
                ArrayConverter.concatenate(undefinedGroup, dummyLength, dummyPublicKey);

        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        EllipticCurvesExtensionMessage ellipticCurvesExtension =
                clientHello.getExtension(EllipticCurvesExtensionMessage.class);
        ellipticCurvesExtension.setSupportedGroups(Modifiable.insert(undefinedGroup, 0));

        KeyShareExtensionMessage keyShareExtension =
                clientHello.getExtension(KeyShareExtensionMessage.class);
        keyShareExtension.setKeyShareListBytes(Modifiable.insert(completeEntry, 0));

        runner.execute(workflowTrace, config).validateFinal(Validator::executedAsPlanned);
    }

    @AnvilTest(id = "8446-Pew9n1pYvc")
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isSecpCurve")
    @Tag("new")
    public void rejectsPointsNotOnCurve(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();

        InvalidCurvePoint groupSpecificPoint = InvalidCurvePoint.largeOrder(selectedGroup);
        EllipticCurve curve = CurveFactory.getCurve(selectedGroup);
        Point invalidPoint =
                new Point(
                        new FieldElementFp(
                                groupSpecificPoint.getPublicPointBaseX(), curve.getModulus()),
                        new FieldElementFp(
                                groupSpecificPoint.getPublicPointBaseY(), curve.getModulus()));
        // note that we do not test with compressed points on the twist as the
        // x coordinate can be valid for a point on both curves
        byte[] serializedPublicKey =
                PointFormatter.formatToByteArray(
                        selectedGroup, invalidPoint, ECPointFormat.UNCOMPRESSED);
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        List<KeyShareEntry> preparedEntryList = new LinkedList<>();
        KeyShareEntry maliciousKeyShare =
                new KeyShareEntry(selectedGroup, config.getKeySharePrivate());
        maliciousKeyShare.setPublicKey(Modifiable.explicit(serializedPublicKey));
        preparedEntryList.add(maliciousKeyShare);
        clientHello.getExtension(KeyShareExtensionMessage.class).setKeyShareList(preparedEntryList);

        workflowTrace.addTlsAction(new SendAction(clientHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            if (WorkflowTraceUtil.didReceiveMessage(
                                    HandshakeMessageType.SERVER_HELLO, i.getWorkflowTrace())) {
                                assertTrue(
                                        "Server sent a Server Hello that is not a Hello Retry Request",
                                        i.getWorkflowTrace()
                                                .getLastReceivedMessage(ServerHelloMessage.class)
                                                .isTls13HelloRetryRequest());
                            } else {
                                Validator.receivedFatalAlert(i);
                            }
                        });
    }

    @AnvilTest(id = "8446-5Vqv9qrKQQ")
    @IncludeParameter("FFDHE_SHARE_OUT_OF_BOUNDS")
    @ManualConfig(identifiers = "FFDHE_SHARE_OUT_OF_BOUNDS")
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getFfdheGroups")
    @Tag("new")
    public void ffdheShareOutOfBounds(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        FFDHEGroup ffdheGroup = GroupFactory.getGroup(selectedGroup);
        ShareOutOfBoundsDerivation.OutOfBoundsType type =
                parameterCombination
                        .getParameter(ShareOutOfBoundsDerivation.class)
                        .getSelectedValue();

        WorkflowTrace worklfowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        worklfowTrace.addTlsAction(new SendAction(clientHello));

        List<KeyShareEntry> keyShareList = new LinkedList<>();
        KeyShareEntry invalidEntry =
                new KeyShareEntry(selectedGroup, config.getDefaultKeySharePrivateKey());

        BigInteger publicKey = null;
        switch (type) {
            case SHARE_IS_ZERO:
                publicKey = BigInteger.ZERO;
                break;
            case SHARE_IS_ONE:
                publicKey = BigInteger.ONE;
                break;
            case SHARE_PLUS_P:
                publicKey = ffdheGroup.getP().add(BigInteger.ONE);
                break;
        }

        invalidEntry.setPublicKey(
                Modifiable.explicit(
                        ArrayConverter.bigIntegerToNullPaddedByteArray(
                                publicKey, ffdheGroup.getP().bitLength() / Bits.IN_A_BYTE)));
        keyShareList.add(invalidEntry);
        clientHello.getExtension(KeyShareExtensionMessage.class).setKeyShareList(keyShareList);
        worklfowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(worklfowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    public List<DerivationParameter<Config, NamedGroup>> getFfdheGroups(DerivationScope scope) {
        List<DerivationParameter<Config, NamedGroup>> derivationParameters = new LinkedList<>();
        context.getFeatureExtractionResult()
                .getTls13FfdheNamedGroups()
                .forEach(group -> derivationParameters.add(new NamedGroupDerivation(group)));
        return derivationParameters;
    }

    @AnvilTest(id = "8446-sa4RjSVVNr")
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isXCurve")
    @Tag("new")
    public void abortsWhenSharedSecretIsZero(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();

        TwistedCurvePoint groupSpecificPoint = TwistedCurvePoint.smallOrder(selectedGroup);
        RFC7748Curve curve = (RFC7748Curve) CurveFactory.getCurve(selectedGroup);
        Point invalidPoint =
                new Point(
                        new FieldElementFp(
                                groupSpecificPoint.getPublicPointBaseX(), curve.getModulus()),
                        new FieldElementFp(
                                groupSpecificPoint.getPublicPointBaseY(), curve.getModulus()));

        byte[] serializedPublicKey = curve.encodeCoordinate(invalidPoint.getFieldX().getData());
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        List<KeyShareEntry> preparedEntryList = new LinkedList<>();
        KeyShareEntry maliciousKeyShare =
                new KeyShareEntry(selectedGroup, config.getKeySharePrivate());
        maliciousKeyShare.setPublicKey(Modifiable.explicit(serializedPublicKey));
        preparedEntryList.add(maliciousKeyShare);
        clientHello.getExtension(KeyShareExtensionMessage.class).setKeyShareList(preparedEntryList);

        workflowTrace.addTlsAction(new SendAction(clientHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            if (WorkflowTraceUtil.didReceiveMessage(
                                    HandshakeMessageType.SERVER_HELLO, i.getWorkflowTrace())) {
                                assertTrue(
                                        "Server sent a Server Hello that is not a Hello Retry Request",
                                        i.getWorkflowTrace()
                                                .getLastReceivedMessage(ServerHelloMessage.class)
                                                .isTls13HelloRetryRequest());
                            } else {
                                Validator.receivedFatalAlert(i);
                            }
                        });
    }

    public boolean isXCurve(NamedGroup group) {
        return group.name().contains("ECDH_X");
    }

    public boolean isSecpCurve(NamedGroup group) {
        // we also include deprecated secp groups here if supported by peer
        return group.isCurve() && group.name().contains("SECP");
    }
}
