/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
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
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.InvalidCurvePoint;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.TwistedCurvePoint;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.LegacyDerivationScope;
import de.rub.nds.tlstest.framework.model.TlsModelType;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.keyexchange.dhe.ShareOutOfBoundsDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8446, section = "4.2.8. Key Share")
public class KeyShare extends Tls13Test {

    @Test
    @TestDescription(
            "Each KeyShareEntry value MUST correspond "
                    + "to a group offered in the \"supported_groups\" extension "
                    + "and MUST appear in the same order. [...]"
                    + "Clients MUST NOT offer multiple KeyShareEntry values "
                    + "for the same group.  Clients MUST NOT offer any KeyShareEntry values "
                    + "for groups not listed in the client's \"supported_groups\" extension.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void testOrderOfKeyshareEntries() {
        ClientHelloMessage chm = context.getReceivedClientHelloMessage();
        EllipticCurvesExtensionMessage groups =
                chm.getExtension(EllipticCurvesExtensionMessage.class);
        KeyShareExtensionMessage keyshare = chm.getExtension(KeyShareExtensionMessage.class);

        try {
            List<KeyShareEntry> keyshares = keyshare.getKeyShareList();
            List<NamedGroup> namedGroups =
                    NamedGroup.namedGroupsFromByteArray(groups.getSupportedGroups().getValue());

            int index = -1;
            List<NamedGroup> checkedGroups = new ArrayList<>();
            for (KeyShareEntry i : keyshares) {
                int tmpIndex = namedGroups.indexOf(i.getGroupConfig());
                assertTrue("Keyshare group not part of supported groups", tmpIndex > -1);
                assertTrue("Keyshares are in the wrong order", tmpIndex > index);
                assertFalse(
                        "Two Keyshare entries for the same group found",
                        checkedGroups.contains(i.getGroupConfig()));

                index = tmpIndex;
                checkedGroups.add(i.getGroupConfig());
            }
        } catch (Exception e) {
            throw new AssertionError("Exception occurred", e);
        }
    }

    @TlsTest(
            description =
                    "If using (EC)DHE key establishment, servers offer exactly one KeyShareEntry in the ServerHello. "
                            + "This value MUST be in the same group as the KeyShareEntry value offered by the client "
                            + "that the server has selected for the negotiated key exchange.")
    @ScopeLimitations(TlsParameterType.NAMED_GROUP)
    @ModelFromScope(baseModel = TlsModelType.CERTIFICATE)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void selectInvalidKeyshare(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage chm = context.getReceivedClientHelloMessage();
        List<NamedGroup> groups = context.getFeatureExtractionResult().getNamedGroups();
        KeyShareExtensionMessage keyshare = chm.getExtension(KeyShareExtensionMessage.class);

        for (KeyShareEntry i : keyshare.getKeyShareList()) {
            groups.remove(i.getGroupConfig());
        }

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        if (groups.size() == 0) {
            KeyShareExtensionMessage keyShareExt =
                    workflowTrace
                            .getFirstSendMessage(ServerHelloMessage.class)
                            .getExtension(KeyShareExtensionMessage.class);
            keyShareExt.setKeyShareListBytes(Modifiable.explicit(new byte[] {0x50, 0x50, 0, 1, 1}));
        } else {
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

            KeyShareExtensionMessage keyShareExt =
                    workflowTrace
                            .getFirstSendMessage(ServerHelloMessage.class)
                            .getExtension(KeyShareExtensionMessage.class);
            keyShareExt.setKeyShareListBytes(Modifiable.explicit(stream.toByteArray()));
        }

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(
            description =
                    "For the curves secp256r1, secp384r1, and secp521r1, peers MUST "
                            + "validate each other's public value Q by ensuring that the point is a "
                            + "valid point on the elliptic curve.")
    @DynamicValueConstraints(affectedTypes = TlsParameterType.NAMED_GROUP, methods = "isSecpCurve")
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @Tag("new")
    public void rejectsPointsNotOnCurve(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.SHORT_HELLO);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();

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

        ServerHelloMessage serverHello = workflowTrace.getLastSendMessage(ServerHelloMessage.class);
        List<KeyShareEntry> preparedEntryList = new LinkedList<>();
        KeyShareEntry maliciousKeyShare =
                new KeyShareEntry(selectedGroup, config.getKeySharePrivate());
        maliciousKeyShare.setPublicKey(Modifiable.explicit(serializedPublicKey));
        preparedEntryList.add(maliciousKeyShare);
        serverHello.getExtension(KeyShareExtensionMessage.class).setKeyShareList(preparedEntryList);

        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    public boolean isSecpCurve(NamedGroup group) {
        // we also include deprecated secp groups here if supported by peer
        return group.isCurve() && group.name().contains("SECP");
    }

    @TlsTest(
            description =
                    "For X25519 and X448, [...]"
                            + "For these curves, implementations SHOULD use the approach specified "
                            + "in [RFC7748] to calculate the Diffie-Hellman shared secret. "
                            + "Implementations MUST check whether the computed Diffie-Hellman shared "
                            + "secret is the all-zero value and abort if so")
    @RFC(number = 8446, section = "7.4.2.  Elliptic Curve Diffie-Hellman")
    @DynamicValueConstraints(affectedTypes = TlsParameterType.NAMED_GROUP, methods = "isXCurve")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void abortsWhenSharedSecretIsZero(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.SHORT_HELLO);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();

        TwistedCurvePoint groupSpecificPoint = TwistedCurvePoint.smallOrder(selectedGroup);
        RFC7748Curve curve = (RFC7748Curve) CurveFactory.getCurve(selectedGroup);
        Point invalidPoint =
                new Point(
                        new FieldElementFp(
                                groupSpecificPoint.getPublicPointBaseX(), curve.getModulus()),
                        new FieldElementFp(
                                groupSpecificPoint.getPublicPointBaseY(), curve.getModulus()));

        byte[] serializedPublicKey = curve.encodeCoordinate(invalidPoint.getFieldX().getData());
        ServerHelloMessage serverHello = workflowTrace.getLastSendMessage(ServerHelloMessage.class);
        List<KeyShareEntry> preparedEntryList = new LinkedList<>();
        KeyShareEntry maliciousKeyShare =
                new KeyShareEntry(selectedGroup, config.getKeySharePrivate());
        maliciousKeyShare.setPublicKey(Modifiable.explicit(serializedPublicKey));
        preparedEntryList.add(maliciousKeyShare);
        serverHello.getExtension(KeyShareExtensionMessage.class).setKeyShareList(preparedEntryList);

        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    public boolean isXCurve(NamedGroup group) {
        return group.name().contains("ECDH_X");
    }

    @Test
    @TestDescription(
            "secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),"
                    + " x25519(0x001D), x448(0x001E),")
    @RFC(number = 8446, section = "4.2.7. Supported Groups")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @DeprecatedFeatureCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    public void offeredDeprecatedGroups() {
        ClientHelloMessage chm = context.getReceivedClientHelloMessage();
        boolean foundDeprecated = false;
        for (KeyShareEntry ks :
                chm.getExtension(KeyShareExtensionMessage.class).getKeyShareList()) {
            if (ks.getGroupConfig() != null && !ks.getGroupConfig().isTls13()) {
                foundDeprecated = true;
                break;
            }
        }
        assertFalse("Deprecated or invalid group used for key share", foundDeprecated);
    }

    @TlsTest(
            description =
                    "Peers MUST validate each other's public key Y by ensuring that 1 < Y "
                            + "< p-1.")
    @RFC(number = 8446, section = "4.2.8.1.  Diffie-Hellman Parameters")
    @ScopeExtensions(TlsParameterType.FFDHE_SHARE_OUT_OF_BOUNDS)
    @ExplicitValues(affectedTypes = TlsParameterType.NAMED_GROUP, methods = "getFfdheGroups")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void ffdheShareOutOfBounds(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        FFDHEGroup ffdheGroup = GroupFactory.getGroup(selectedGroup);
        ShareOutOfBoundsDerivation.OutOfBoundsType type =
                derivationContainer
                        .getDerivation(ShareOutOfBoundsDerivation.class)
                        .getSelectedValue();

        WorkflowTrace worklfowTrace = runner.generateWorkflowTrace(WorkflowTraceType.SHORT_HELLO);
        ServerHelloMessage serverHello =
                worklfowTrace.getFirstSendMessage(ServerHelloMessage.class);

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
        serverHello.getExtension(KeyShareExtensionMessage.class).setKeyShareList(keyShareList);
        worklfowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(worklfowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    public List<DerivationParameter<TlsAnvilConfig, NamedGroup>> getFfdheGroups(
            LegacyDerivationScope scope) {
        List<DerivationParameter<TlsAnvilConfig, NamedGroup>> derivationParameters =
                new LinkedList<>();
        context.getFeatureExtractionResult()
                .getTls13FfdheNamedGroups()
                .forEach(group -> derivationParameters.add(new NamedGroupDerivation(group)));
        return derivationParameters;
    }
}
