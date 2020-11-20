/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.coffee4j.reporter;

import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.TestInputGroupContext;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.List;

public class TlsTestsuiteReporter implements ExecutionReporter {
    private static final Logger LOGGER = LogManager.getLogger();

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
