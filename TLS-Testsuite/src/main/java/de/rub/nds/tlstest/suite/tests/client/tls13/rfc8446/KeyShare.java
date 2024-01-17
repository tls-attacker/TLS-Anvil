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

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
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
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.InvalidCurvePoint;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.TwistedCurvePoint;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.keyexchange.dhe.ShareOutOfBoundsDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class KeyShare extends Tls13Test {

    @NonCombinatorialAnvilTest(id = "8446-WtTcgsZFA3")
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

    @AnvilTest(id = "8446-F9bWYMiB45")
    @ExcludeParameter("NAMED_GROUP")
    @ModelFromScope(modelType = "CERTIFICATE")
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

    @AnvilTest(id = "8446-YMYRto48Jg")
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isSecpCurve")
    @Tag("new")
    public void rejectsPointsNotOnCurve(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.SHORT_HELLO);
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
        // we model null as 'no group'
        return group != null && group.isCurve() && group.name().contains("SECP");
    }

    @AnvilTest(id = "8446-h4RyAhoVZy")
    @DynamicValueConstraints(affectedIdentifiers = "NAMED_GROUP", methods = "isXCurve")
    @Tag("new")
    public void abortsWhenSharedSecretIsZero(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.SHORT_HELLO);
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
        // we model null as 'no group'
        return group != null && group.name().contains("ECDH_X");
    }

    @NonCombinatorialAnvilTest(id = "8446-JKvCjP5mKE")
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

    @AnvilTest(id = "8446-QxfMDM9cBK")
    @IncludeParameter("FFDHE_SHARE_OUT_OF_BOUNDS")
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

    public List<DerivationParameter<Config, NamedGroup>> getFfdheGroups(DerivationScope scope) {
        List<DerivationParameter<Config, NamedGroup>> derivationParameters = new LinkedList<>();
        context.getFeatureExtractionResult()
                .getTls13FfdheNamedGroups()
                .forEach(group -> derivationParameters.add(new NamedGroupDerivation(group)));
        return derivationParameters;
    }
}
