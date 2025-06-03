/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.protocol.constants.PointFormat;
import de.rub.nds.protocol.crypto.ec.*;
import de.rub.nds.protocol.crypto.ffdh.FfdhGroup;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
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

@ServerTest
public class KeyShare extends Tls13Test {

    @AnvilTest(id = "8446-9hMnjrCbMV")
    @ExcludeParameter("NAMED_GROUP")
    /*
        Servers MAY check for violations of these rules and abort the
        handshake with an "illegal_parameter" alert if one is violated.
    */
    @EnforcedSenderRestriction
    public void testOrderOfKeyshareEntries(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

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
        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        AlertMessage alert = trace.getFirstReceivedMessage(AlertMessage.class);
        ServerHelloMessage shm = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        if (alert != null && shm == null) {
            assertEquals(
                    AlertLevel.FATAL.getValue(),
                    alert.getLevel().getValue().byteValue(),
                    "No fatal alert received");
            Validator.testAlertDescription(
                    state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
            testCase.addAdditionalResultInfo("Received alert");
            return;
        }

        assertTrue(
                state.getWorkflowTrace().executedAsPlanned(),
                AssertMsgs.WORKFLOW_NOT_EXECUTED + ", server likely selected the wrong key share");
    }

    @AnvilTest(id = "8446-R2rb1WZoQo")
    public void serverOnlyOffersOneKeyshare(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        List<NamedGroup> supportedTls13 = context.getFeatureExtractionResult().getTls13Groups();

        // place selected group at the top to avoid (optional) HRR
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        supportedTls13.remove(selectedGroup);
        supportedTls13.add(0, selectedGroup);

        c.setDefaultClientNamedGroups(supportedTls13);
        performOneKeyshareTest(c, runner, testCase);
    }

    @AnvilTest(id = "8446-TKn1mNn5mY")
    @ExcludeParameter("NAMED_GROUP")
    public void serverOnlyOffersOneKeyshareAllGroupsAtOnce(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        List<NamedGroup> supportedTls13 = context.getFeatureExtractionResult().getTls13Groups();
        c.setDefaultClientKeyShareNamedGroups(supportedTls13);
        c.setDefaultClientNamedGroups(supportedTls13);
        performOneKeyshareTest(c, runner, testCase);
    }

    public void performOneKeyshareTest(Config c, WorkflowRunner runner, AnvilTestCase testCase) {
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        State state = runner.execute(workflowTrace, c);

        ServerHelloMessage serverHello =
                state.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
        assertTrue(serverHello != null, "No ServerHello has been received");
        KeyShareExtensionMessage keyshare =
                serverHello.getExtension(KeyShareExtensionMessage.class);
        if (serverHello.isTls13HelloRetryRequest()) {
            testCase.addAdditionalResultInfo("Server enforced own preferred group");
            assertTrue(
                    c.getDefaultClientNamedGroups()
                            .contains(
                                    keyshare.getKeyShareList().stream()
                                            .map(KeyShareEntry::getGroupConfig)
                                            .collect(Collectors.toList())
                                            .get(0)),
                    "Server requested an unproposed group in HelloRetryRequest");
        } else {
            Validator.executedAsPlanned(state, testCase);
            assertTrue(
                    c.getDefaultClientKeyShareNamedGroups()
                            .contains(
                                    keyshare.getKeyShareList().stream()
                                            .map(KeyShareEntry::getGroupConfig)
                                            .collect(Collectors.toList())
                                            .get(0)),
                    "Server selected group for which no Key Share was sent outside of HelloRetryRequest");
        }
        assertEquals(
                1,
                keyshare.getKeyShareList().size(),
                "Server offered more than one keyshare entry");
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
    public void serverAcceptsDeprecatedGroups(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        List<NamedGroup> groups = NamedGroup.getImplemented();
        groups.removeIf(i -> i.isTls13());
        performDeprecatedGroupsTest(c, runner);
    }

    @AnvilTest(id = "8446-1vps8J91dU")
    @ExcludeParameter("NAMED_GROUP")
    public void serverAcceptsDeprecatedGroupsAllAtOnce(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        List<NamedGroup> groups = NamedGroup.getImplemented();
        groups.removeIf(i -> i.isTls13());
        c.setDefaultClientNamedGroups(groups);
        c.setDefaultClientKeyShareNamedGroups(groups);

        performDeprecatedGroupsTest(c, runner);
    }

    public void performDeprecatedGroupsTest(Config c, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        List<NamedGroup> groups = c.getDefaultClientKeyShareNamedGroups();

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        if (WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.SERVER_HELLO)
                && trace.getFirstReceivedMessage(ServerHelloMessage.class)
                        .containsExtension(ExtensionType.KEY_SHARE)) {
            KeyShareExtensionMessage ksExt =
                    trace.getFirstReceivedMessage(ServerHelloMessage.class)
                            .getExtension(KeyShareExtensionMessage.class);
            assertFalse(
                    groups.contains(
                            ksExt.getKeyShareList().stream()
                                    .map(KeyShareEntry::getGroupConfig)
                                    .collect(Collectors.toList())
                                    .get(0)),
                    "Server accepted a deprecated group");
            // other groups may not be used - even in HelloRetryRequest
            assertTrue(
                    groups.contains(
                            ksExt.getKeyShareList().stream()
                                    .map(KeyShareEntry::getGroupConfig)
                                    .collect(Collectors.toList())
                                    .get(0)),
                    "Server selected an unproposed group");
        }
    }

    @AnvilTest(id = "8446-tCzswEB5Ua")
    public void includeUnknownGroup(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        byte[] undefinedGroup = new byte[] {(byte) 123, 124};
        byte[] dummyLength = new byte[] {(byte) 0, 56};
        byte[] dummyPublicKey = new byte[56];

        byte[] completeEntry =
                ArrayConverter.concatenate(undefinedGroup, dummyLength, dummyPublicKey);

        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        EllipticCurvesExtensionMessage ellipticCurvesExtension =
                clientHello.getExtension(EllipticCurvesExtensionMessage.class);
        ellipticCurvesExtension.setSupportedGroups(Modifiable.insert(undefinedGroup, 0));

        KeyShareExtensionMessage keyShareExtension =
                clientHello.getExtension(KeyShareExtensionMessage.class);
        keyShareExtension.setKeyShareListBytes(Modifiable.insert(completeEntry, 0));

        State state = runner.execute(workflowTrace, config);
        Validator.executedAsPlanned(state, testCase);
    }

    @AnvilTest(id = "8446-Pew9n1pYvc")
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isSecpCurve")
    @Tag("new")
    public void rejectsPointsNotOnCurve(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();

        InvalidCurvePoint groupSpecificPoint = InvalidCurvePoint.largeOrder(selectedGroup);
        EllipticCurve curve = (EllipticCurve) selectedGroup.getGroupParameters().getGroup();
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
                        selectedGroup.getGroupParameters(), invalidPoint, PointFormat.UNCOMPRESSED);
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        List<KeyShareEntry> preparedEntryList = new LinkedList<>();
        KeyShareEntry maliciousKeyShare =
                new KeyShareEntry(
                        selectedGroup, config.getDefaultKeySharePrivateKey(selectedGroup));
        maliciousKeyShare.setPublicKey(Modifiable.explicit(serializedPublicKey));
        preparedEntryList.add(maliciousKeyShare);
        clientHello.getExtension(KeyShareExtensionMessage.class).setKeyShareList(preparedEntryList);

        workflowTrace.addTlsAction(new SendAction(clientHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            assertTrue(
                    state.getWorkflowTrace()
                            .getLastReceivedMessage(ServerHelloMessage.class)
                            .isTls13HelloRetryRequest(),
                    "Server sent a Server Hello that is not a Hello Retry Request");
        } else {
            Validator.receivedFatalAlert(state, testCase);
        }
    }

    @AnvilTest(id = "8446-5Vqv9qrKQQ")
    @IncludeParameter("FFDHE_SHARE_OUT_OF_BOUNDS")
    @ManualConfig(identifiers = "FFDHE_SHARE_OUT_OF_BOUNDS")
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getFfdheGroups")
    @Tag("new")
    public void ffdheShareOutOfBounds(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        FfdhGroup ffdheGroup = (FfdhGroup) selectedGroup.getGroupParameters().getGroup();
        ShareOutOfBoundsDerivation.OutOfBoundsType type =
                parameterCombination
                        .getParameter(ShareOutOfBoundsDerivation.class)
                        .getSelectedValue();

        WorkflowTrace worklfowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        worklfowTrace.addTlsAction(new SendAction(clientHello));

        List<KeyShareEntry> keyShareList = new LinkedList<>();
        KeyShareEntry invalidEntry =
                new KeyShareEntry(
                        selectedGroup, config.getDefaultKeySharePrivateKey(selectedGroup));

        BigInteger publicKey = null;
        switch (type) {
            case SHARE_IS_ZERO:
                publicKey = BigInteger.ZERO;
                break;
            case SHARE_IS_ONE:
                publicKey = BigInteger.ONE;
                break;
            case SHARE_PLUS_P:
                publicKey = ffdheGroup.getModulus().add(BigInteger.ONE);
                break;
        }

        invalidEntry.setPublicKey(
                Modifiable.explicit(
                        ArrayConverter.bigIntegerToNullPaddedByteArray(
                                publicKey, ffdheGroup.getModulus().bitLength() / Bits.IN_A_BYTE)));
        keyShareList.add(invalidEntry);
        clientHello.getExtension(KeyShareExtensionMessage.class).setKeyShareList(keyShareList);
        worklfowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(worklfowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
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
    public void abortsWhenSharedSecretIsZero(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();

        TwistedCurvePoint groupSpecificPoint = TwistedCurvePoint.smallOrder(selectedGroup);
        RFC7748Curve curve = (RFC7748Curve) selectedGroup.getGroupParameters().getGroup();
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
                new KeyShareEntry(
                        selectedGroup, config.getDefaultKeySharePrivateKey(selectedGroup));
        maliciousKeyShare.setPublicKey(Modifiable.explicit(serializedPublicKey));
        preparedEntryList.add(maliciousKeyShare);
        clientHello.getExtension(KeyShareExtensionMessage.class).setKeyShareList(preparedEntryList);

        workflowTrace.addTlsAction(new SendAction(clientHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            assertTrue(
                    state.getWorkflowTrace()
                            .getLastReceivedMessage(ServerHelloMessage.class)
                            .isTls13HelloRetryRequest(),
                    "Server sent a Server Hello that is not a Hello Retry Request");
        } else {
            Validator.receivedFatalAlert(state, testCase);
        }
    }

    public boolean isXCurve(NamedGroup group) {
        return group != null && group.name().contains("ECDH_X");
    }

    public boolean isSecpCurve(NamedGroup group) {
        // we also include deprecated secp groups here if supported by peer
        return group != null && group.isCurve() && group.name().contains("SECP");
    }
}
