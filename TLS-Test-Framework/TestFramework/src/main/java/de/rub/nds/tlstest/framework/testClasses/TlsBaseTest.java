/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.testClasses;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.junitExtensions.EndpointCondition;
import de.rub.nds.tlstest.framework.junitExtensions.EnforcedSenderRestrictionConditionExtension;
import de.rub.nds.tlstest.framework.junitExtensions.ExtensionContextResolver;
import de.rub.nds.tlstest.framework.junitExtensions.KexCondition;
import de.rub.nds.tlstest.framework.junitExtensions.MethodConditionExtension;
import de.rub.nds.tlstest.framework.junitExtensions.TestWatcher;
import de.rub.nds.tlstest.framework.junitExtensions.TlsVersionCondition;
import de.rub.nds.tlstest.framework.junitExtensions.ValueConstraintsConditionExtension;
import de.rub.nds.tlstest.framework.junitExtensions.WorkflowRunnerResolver;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ExtendWith({
        TestWatcher.class,
        EndpointCondition.class,
        TlsVersionCondition.class,
        KexCondition.class,
        MethodConditionExtension.class,
        EnforcedSenderRestrictionConditionExtension.class,
        ValueConstraintsConditionExtension.class,
        ExtensionContextResolver.class,
        WorkflowRunnerResolver.class
})
public abstract class TlsBaseTest {
    protected static final Logger LOGGER = LogManager.getLogger();

    protected TestContext context;
    
    protected DerivationContainer derivationContainer;
    
    protected ExtensionContext extensionContext;
    
    @BeforeEach
    public void setExtensionContext(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }
    
    public Config getPreparedConfig(ArgumentsAccessor argAccessor, WorkflowRunner runner) {
        Config toPrepare = getConfig();
        return prepareConfig(toPrepare, argAccessor, runner);
    }
    
    public Config prepareConfig(Config config, ArgumentsAccessor argAccessor, WorkflowRunner runner) {
        derivationContainer = new DerivationContainer(argAccessor.toList(), new DerivationScope(extensionContext));
        derivationContainer.applyToConfig(config, context);
        runner.setPreparedConfig(config);
        runner.setDerivationContainer(derivationContainer);
        return config;
    }
    
    public void adjustPreSharedKeyModes(Config config) {
        if(context.getSiteReport().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE) == TestResults.TRUE &&
                context.getSiteReport().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK) == TestResults.FALSE) {
            config.setPSKKeyExchangeModes(Arrays.asList(PskKeyExchangeMode.PSK_DHE_KE));
        }
    }
    
    public TlsBaseTest() {
        this.context = TestContext.getInstance();
    }

    public void setTestContext(TestContext testCotext) {
        this.context = testCotext;
    }

    public TestContext getTestContext() {
        return context;
    }
    
    public abstract Config getConfig();
}

