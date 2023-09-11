/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.ExplicitValues;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.ManualConfig;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElementFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.crypto.ec.RFC7748Curve;
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
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
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
@RFC(number = 8446, section = "4.2.8. Key Share")
public class KeyShare extends Tls13Test {

    @AnvilTest(
            description =
                    "Each KeyShareEntry value MUST correspond "
                            + "to a group offered in the \"supported_groups\" extension "
                            + "and MUST appear in the same order.")
    @ExcludeParameter("NAMED_GROUP")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
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

    @AnvilTest(
            description =
                    "If (EC)DHE key establishment "
                            + "is in use, then the ServerHello contains a \"key_share\" extension with "
                            + "the server's ephemeral Diffie-Hellman share; the server's share MUST "
                            + "be in the same group as one of the client's shares. [...]"
                            + "If using (EC)DHE key establishment, servers offer exactly one KeyShareEntry in the ServerHello. "
                            + "This value MUST be in the same group as the KeyShareEntry value offered by the client "
                            + "that the server has selected for the negotiated key exchange.")
    @RFC(number = 8446, section = "2. Protocol Overview and 4.2.8. Key Share")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
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

    @AnvilTest(
            description =
                    "If using (EC)DHE key establishment, servers offer exactly one KeyShareEntry in the ServerHello. "
                            + "This value MUST be in the same group as the KeyShareEntry value offered by the client "
                            + "that the server has selected for the negotiated key exchange. [...]"
                            + "Servers "
                            + "MUST NOT send a KeyShareEntry for any group not indicated in the "
                            + "client's \"supported_groups\" extension")
    @ExcludeParameter("NAMED_GROUP")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
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

    public List<DerivationParameter<Config, NamedGroup>> getLegacyGroups(
            DerivationScope scope) {
        List<DerivationParameter<Config, NamedGroup>> parameterValues = new LinkedList<>();
        List<NamedGroup> groups = NamedGroup.getImplemented();
        groups.removeIf(i -> i.isTls13());
        groups.forEach(i -> parameterValues.add(new NamedGroupDerivation(i)));
        return parameterValues;
    }

    @AnvilTest(
            description =
                    "secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),"
                            + " x25519(0x001D), x448(0x001E),")
    @RFC(number = 8446, section = "4.2.7. Supported Groups")
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getLegacyGroups")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @CryptoCategory(SeverityLevel.HIGH)
    @DeprecatedFeatureCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.LOW)
    public void serverAcceptsDeprecatedGroups(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        List<NamedGroup> groups = NamedGroup.getImplemented();
        groups.removeIf(i -> i.isTls13());
        performDeprecatedGroupsTest(c, runner);
    }

    @AnvilTest(
            description =
                    "secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),"
                            + " x25519(0x001D), x448(0x001E),")
    @RFC(number = 8446, section = "4.2.7. Supported Groups")
    @ExcludeParameter("NAMED_GROUP")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @CryptoCategory(SeverityLevel.HIGH)
    @DeprecatedFeatureCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.LOW)
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

    @AnvilTest(
            description =
                    "A server receiving a ClientHello MUST correctly ignore all "
                            + "unrecognized cipher suites, extensions, and other parameters. "
                            + "Otherwise, it may fail to interoperate with newer clients.")
    @RFC(number = 8446, section = "9.3.  Protocol Invariants")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
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

    @AnvilTest(
            description =
                    "For the curves secp256r1, secp384r1, and secp521r1, peers MUST "
                            + "validate each other's public value Q by ensuring that the point is a "
                            + "valid point on the elliptic curve.")
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isSecpCurve")
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.CRITICAL)
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

    @AnvilTest(
            description =
                    "Peers MUST validate each other's public key Y by ensuring that 1 < Y "
                            + "< p-1.")
    @RFC(number = 8446, section = "4.2.8.1.  Diffie-Hellman Parameters")
    @IncludeParameter("FFDHE_SHARE_OUT_OF_BOUNDS")
    @ManualConfig(identifiers = "FFDHE_SHARE_OUT_OF_BOUNDS")
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getFfdheGroups")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
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

    public List<DerivationParameter<Config, NamedGroup>> getFfdheGroups(
            DerivationScope scope) {
        List<DerivationParameter<Config, NamedGroup>> derivationParameters =
                new LinkedList<>();
        context.getFeatureExtractionResult()
                .getTls13FfdheNamedGroups()
                .forEach(group -> derivationParameters.add(new NamedGroupDerivation(group)));
        return derivationParameters;
    }

    @AnvilTest(
            description =
                    "For X25519 and X448, [...]"
                            + "For these curves, implementations SHOULD use the approach specified "
                            + "in [RFC7748] to calculate the Diffie-Hellman shared secret. "
                            + "Implementations MUST check whether the computed Diffie-Hellman shared "
                            + "secret is the all-zero value and abort if so")
    @RFC(number = 8446, section = "7.4.2.  Elliptic Curve Diffie-Hellman")
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isXCurve")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
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
