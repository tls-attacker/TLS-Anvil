/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.coffee4j.reporter;

import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.TestInputGroupContext;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.PrintStream;
import java.util.List;

/**
 *
 * @author marcel
 */
public class TlsTestsuiteReporter implements ExecutionReporter {
    private final ExtensionContext extensionContext;
    
    public TlsTestsuiteReporter(ExtensionContext context) {
        extensionContext = context;
    }
    
    @Override
    public void faultCharacterizationFinished(TestInputGroupContext context, List<Combination> failureInducingCombinations) {
        AnnotatedStateContainer.forExtensionContext(extensionContext).setFailureInducingCombinations(failureInducingCombinations);
    }

    @Override
    public void testInputGroupFinished(TestInputGroupContext context) {
        AnnotatedStateContainer.forExtensionContext(extensionContext).finished();
    }
}
