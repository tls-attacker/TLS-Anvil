/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeContextValueAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.ParameterModelFactory;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rwth.swc.coffee4j.engine.characterization.delta.ImprovedDeltaDebugging;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.constraint.DiagnosticConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.ipog.Ipog;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.configuration.characterization.EnableFaultCharacterization;
import de.rwth.swc.coffee4j.junit.provider.configuration.generator.Generator;
import de.rwth.swc.coffee4j.junit.provider.configuration.reporter.Reporter;
import de.rwth.swc.coffee4j.junit.provider.model.ModelFromMethod;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.report.PrintStreamExecutionReporter;
import org.junit.Before;
import org.junit.Rule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.rules.TestName;
import de.rub.nds.tlstest.framework.coffee4j.ModelFromScope;
import de.rub.nds.tlstest.framework.coffee4j.TlsTestsuiteReporter;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@RFC(number = 5246, section = "7.4.9 Finished")
public class Finished extends Tls12Test {
    
    @ModelFromScope(scopeLimitations = {DerivationType.ALERT}, scopeExtensions = {DerivationType.CIPHERSUITE})
    @ScopeExtensions
    @TlsTest( description = "Recipients of Finished messages MUST verify that the contents are correct.", securitySeverity = SeverityLevel.CRITICAL)
    @Tag("WIP")
    public void verifyFinishedMessageCorrect(ArgumentsAccessor argumentAccessor) {
        derivationContainer = new DerivationContainer(argumentAccessor);
        Config c = this.getConfig();
        WorkflowRunner runner = new WorkflowRunner(extensionContext, c);

        byte[] modificationBitmask = (byte[])derivationContainer.getDerivation(DerivationType.MAC_BITMASK).getSelectedValue();
        FinishedMessage finishedMessage = new FinishedMessage();
        finishedMessage.setVerifyData(Modifiable.xor(modificationBitmask, 0));

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(
                new SendAction(finishedMessage),
                new ReceiveAction(new AlertMessage())
        );

        runner.executeImmediately(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "For the PRF defined in Section 5, the Hash MUST be the Hash used as the basis for the PRF.", securitySeverity = SeverityLevel.CRITICAL)
    public void invalidPRF(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(
                new ChangeContextValueAction<PRFAlgorithm>("prfAlgorithm", (PRFAlgorithm) null),
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            ChangeContextValueAction<PRFAlgorithm> action = i.getWorkflowTrace().getFirstAction(ChangeContextValueAction.class);
            CipherSuite cipherSuite = i.getInspectedCipherSuite();

            PRFAlgorithm alg = AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12, cipherSuite);
            if (alg == PRFAlgorithm.TLS_PRF_SHA256) {
                action.setNewValue(PRFAlgorithm.TLS_PRF_SHA384);
            } else {
                action.setNewValue(PRFAlgorithm.TLS_PRF_SHA256);
            }
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "It is a fatal error if a Finished message is not preceded by a ChangeCipherSpec " +
            "message at the appropriate point in the handshake.", securitySeverity = SeverityLevel.CRITICAL)
    public void omitCCS(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsActions(
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
    
}
