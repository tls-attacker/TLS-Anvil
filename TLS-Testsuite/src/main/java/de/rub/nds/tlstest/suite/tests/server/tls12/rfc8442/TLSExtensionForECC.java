/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc8442;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;


@ServerTest
public class TLSExtensionForECC extends Tls12Test {
    private static final Logger LOGGER = LogManager.getLogger();

    private void execute(WorkflowRunner runner, Config config) {

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveAction(new AlertMessage(config))
        );

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @RFC(number = 8422, section = "4. TLS Extensions for ECC")
    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello " +
            "message if it does not propose any ECC cipher suites.")
    @Security(SeverityLevel.INFORMATIONAL)
    @KeyExchange(supported = {KeyExchangeType.RSA, KeyExchangeType.DH})
    public void BothECExtensions_WithoutECCCipher(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        execute(runner, c);
    }

    @RFC(number = 8422, section = "4. TLS Extensions for ECC")
    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello " +
            "message if it does not propose any ECC cipher suites.")
    @KeyExchange(supported = {KeyExchangeType.RSA, KeyExchangeType.DH})
    public void ECExtension_WithoutECCCipher(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(false);

        execute(runner, c);
    }

    @RFC(number = 8422, section = "4. TLS Extensions for ECC")
    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello " +
            "message if it does not propose any ECC cipher suites.")
    @KeyExchange(supported = {KeyExchangeType.RSA, KeyExchangeType.DH})
    public void ECPointFormatExtension_WithoutECCCipher(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(false);
        c.setAddECPointFormatExtension(true);

        execute(runner, c);
    }


    @RFC(number = 8422, section = "5.1. Client Hello Extensions")
    @TlsTest(description = "If a server does not understand the Supported Elliptic Curves Extension, " +
            "does not understand the Supported Point Formats Extension, or is unable to complete the ECC handshake " +
            "while restricting itself to the enumerated curves and point formats, " +
            "it MUST NOT negotiate the use of an ECC cipher suite.")
    @Interoperability(SeverityLevel.LOW)
    @ScopeLimitations(DerivationType.NAMED_GROUP)
    @KeyExchange(supported = KeyExchangeType.ECDH)
    public void InvalidEllipticCurve(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm),
                new ReceiveAction(new AlertMessage(c))
        );

        chm.getExtension(EllipticCurvesExtensionMessage.class).setSupportedGroups(Modifiable.explicit(new byte[]{(byte) 123, 124}));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @RFC(number = 8422, section = "5.1. Client Hello Extensions")
    @TlsTest(description = "If a server does not understand the Supported Elliptic Curves Extension, " +
            "does not understand the Supported Point Formats Extension, or is unable to complete the ECC handshake " +
            "while restricting itself to the enumerated curves and point formats, " +
            "it MUST NOT negotiate the use of an ECC cipher suite.")
    @Interoperability(SeverityLevel.CRITICAL)
    @ScopeLimitations(DerivationType.NAMED_GROUP)
    @ManualConfig(DerivationType.CIPHERSUITE)
    @KeyExchange(supported = {KeyExchangeType.RSA, KeyExchangeType.DH})
    public void InvalidEllipticCurve_WithNonECCCiphersuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);
        List<CipherSuite> cipherSuiteList = CipherSuite.getImplemented().stream()
                .filter(i -> KeyExchangeType.forCipherSuite(i) == KeyExchangeType.ECDH)
                .collect(Collectors.toList());
        cipherSuiteList.add(derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue());

        c.setDefaultClientSupportedCiphersuites(cipherSuiteList);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        chm.getExtension(EllipticCurvesExtensionMessage.class).setSupportedGroups(Modifiable.explicit(new byte[]{(byte) 123, 124}));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            WorkflowTrace trace = i.getWorkflowTrace();
            ServerHelloMessage message = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, message);
            assertArrayEquals(
                    AssertMsgs.UnexpectedCipherSuite,
                    derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue().getByteValue(),
                    message.getSelectedCipherSuite().getValue()
            );
        });
    }
    
    @RFC(number = 8422, section = "5.1.1 Supported Elliptic Curves Extension")
    /*@TlsTest(description = " RFC 4492 defined 25 different curves in the NamedCurve registry (now\n" +
            "renamed the \"TLS Supported Groups\" registry, although the enumeration\n" +
            "below is still named NamedCurve) for use in TLS.  Only three have\n" +
            "seen much use.  This specification is deprecating the rest (with\n" +
            "numbers 1-22).  This specification also deprecates the explicit " +
            "curves with identifiers 0xFF01 and 0xFF02.  It also adds the new\n" +
            "curves defined in [RFC7748]", securitySeverity = SeverityLevel.LOW)*/
    @Test
    @Security(SeverityLevel.LOW)
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    @TestDescription("Deprecated groups should not be supported")
    public void supportsDeprecated(WorkflowRunner runner) {
        boolean deprecated = false;
        for(NamedGroup group : context.getSiteReport().getSupportedNamedGroups()) {
            if(group.getIntValue() < NamedGroup.SECP256R1.getIntValue() || group == NamedGroup.EXPLICIT_CHAR2 || group == NamedGroup.EXPLICIT_PRIME) {
                deprecated = true;
                break;
            }
        }
        assertFalse("A deprecated group was accepted", deprecated);
    }

}
