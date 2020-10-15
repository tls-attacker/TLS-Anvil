/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
@RFC(number = 8446, section = "4.2.11 Pre-Shared Key Extension")
public class PreSharedKey extends Tls13Test {

    public ConditionEvaluationResult supportsPsk() {
        if (context.getSiteReport().getResult(AnalyzedProperty.SUPPORTS_TLS13_PSK) == TestResult.TRUE
                || context.getSiteReport().getResult(AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE) == TestResult.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not support PSK handshakes");
        }
    }

    private int getExpectedExtensionCount(Config c) {
        WorkflowConfigurationFactory dummyFactory = new WorkflowConfigurationFactory(c);
        WorkflowTrace dummyTrace = dummyFactory.createWorkflowTrace(WorkflowTraceType.SHORT_HELLO, RunningModeType.CLIENT);
        return dummyTrace.getFirstSendMessage(ClientHelloMessage.class).getExtensions().size();
    }

    @TlsTest(description = "The \"pre_shared_key\" extension MUST be the last extension "
            + "in the ClientHello (this facilitates implementation as described below). "
            + "Servers MUST check that it is the last extension and otherwise fail "
            + "the handshake with an \"illegal_parameter\" alert.")
    @RFC(number = 8446, section = "4.2.11. Pre-Shared Key Extension")
    @MethodCondition(method = "supportsPsk")
    public void isNotLastExtension(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilLastReceivingMessage(WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        AnnotatedStateContainer container = new AnnotatedStateContainer();
        int nonPskExtensions = getExpectedExtensionCount(c) - 1;
        for (int i = 0; i < nonPskExtensions; i++) {
            int myIndex = i;
            runner.setStateModifier(s -> {
                s.addAdditionalTestInfo("Position " + myIndex + " of " + (nonPskExtensions - 1));
                ClientHelloMessage cHello = s.getWorkflowTrace().getLastSendMessage(ClientHelloMessage.class);
                int extensionCount = cHello.getExtensions().size();
                PreSharedKeyExtensionMessage pskExt = (PreSharedKeyExtensionMessage) cHello.getExtensions().get(extensionCount - 1);
                cHello.getExtensions().remove(pskExt);
                cHello.getExtensions().add(myIndex, pskExt);
                return null;
            });

            container.addAll(runner.prepare(workflowTrace, c));
        }
        runner.execute(container).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            System.out.println(trace.toString());
            Validator.receivedFatalAlert(i, false);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    @TlsTest(description = "The \"pre_shared_key\" extension MUST be the last extension "
            + "in the ClientHello (this facilitates implementation as described below). "
            + "Servers MUST check that it is the last extension and otherwise fail "
            + "the handshake with an \"illegal_parameter\" alert.")
    @RFC(number = 8446, section = "4.2.11. Pre-Shared Key Extension")
    @MethodCondition(method = "supportsPsk")
    public void duplicateExtension(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilLastReceivingMessage(WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        AnnotatedStateContainer container = new AnnotatedStateContainer();
        int nonPskExtensions = getExpectedExtensionCount(c) - 1;
        for (int i = 0; i < nonPskExtensions; i++) {
            int myIndex = i;
            runner.setStateModifier(s -> {
                s.addAdditionalTestInfo("Position " + myIndex + " of " + (nonPskExtensions - 1));
                ClientHelloMessage cHello = s.getWorkflowTrace().getLastSendMessage(ClientHelloMessage.class);
                int extensionCount = cHello.getExtensions().size();
                PreSharedKeyExtensionMessage pskExt = (PreSharedKeyExtensionMessage) cHello.getExtensions().get(extensionCount - 1);
                cHello.getExtensions().add(myIndex, pskExt);
                return null;
            });

            container.addAll(runner.prepare(workflowTrace, c));
        }
        runner.execute(container).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i, false);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    @TlsTest(description = "Prior to accepting PSK key establishment, the server MUST validate"
            + "the corresponding binder value")
    @RFC(number = 8446, section = "4.2.11. Pre-Shared Key Extension")
    @MethodCondition(method = "supportsPsk") //todo: this takes ~ 1h 20 for all combinations - we should limit this
    public void invalidBinder(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setLimitPsksToOne(true);
        runner.replaceSupportedCiphersuites = true;
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilLastReceivingMessage(WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());
        
        AnnotatedStateContainer container = new AnnotatedStateContainer();
        for (int i = 0; i < 384; i++) {
            int affectedBit = i;
            runner.setStateModifier(s -> {
                ClientHelloMessage cHello = s.getWorkflowTrace().getLastSendMessage(ClientHelloMessage.class);
                PreSharedKeyExtensionMessage pskExt = cHello.getExtension(PreSharedKeyExtensionMessage.class);
                HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(s.getInspectedCipherSuite());
                int macLen = 0;
                try {
                    macLen = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName()).getMacLength() * 8;
                } catch (NoSuchAlgorithmException ex) {
                    LOGGER.warn("CipherSuite did not yield a known Mac algorithm");
                    macLen = 256;
                }

                if (affectedBit < macLen) {
                    s.addAdditionalTestInfo("Manipulated bit " + (affectedBit + 1) + " of " + macLen + " for " + s.getInspectedCipherSuite());
                    byte[] mask =  new byte[] {(byte)(0x1 << (affectedBit % 8))};
                    pskExt.setBinderListBytes(Modifiable.xor(mask, ExtensionByteLength.PSK_BINDER_LENGTH + (affectedBit / 8)));
                } else {
                    s.setOmitFromTests(true);
                }
                return null;
            });

            container.addAll(runner.prepare(workflowTrace, c));
            break;
        }

        runner.execute(container).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i, false);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    @TlsTest(description = "Prior to accepting PSK key establishment, the server MUST validate"
            + "the corresponding binder value")
    @RFC(number = 8446, section = "4.2.11. Pre-Shared Key Extension")
    @MethodCondition(method = "supportsPsk")
    public void noBinder(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setLimitPsksToOne(true);
        runner.replaceSupportedCiphersuites = true;
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilLastReceivingMessage(WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());
        
        runner.setStateModifier(s -> {
            ClientHelloMessage cHello = s.getWorkflowTrace().getLastSendMessage(ClientHelloMessage.class);
            PreSharedKeyExtensionMessage pskExt = cHello.getExtension(PreSharedKeyExtensionMessage.class);
            pskExt.setBinderListBytes(Modifiable.explicit(new byte[0]));
            pskExt.setBinderListLength(Modifiable.explicit(0));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i, false);
        });

    }
}
