/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.testClasses;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.junitExtensions.EndpointCondition;
import de.rub.nds.tlstest.framework.junitExtensions.ExtensionContextResolver;
import de.rub.nds.tlstest.framework.junitExtensions.KexCondition;
import de.rub.nds.tlstest.framework.junitExtensions.MethodConditionExtension;
import de.rub.nds.tlstest.framework.junitExtensions.TestWatcher;
import de.rub.nds.tlstest.framework.junitExtensions.TlsVersionCondition;
import de.rub.nds.tlstest.framework.junitExtensions.ValueConstraintsConditionExtension;
import de.rub.nds.tlstest.framework.junitExtensions.WorkflowRunnerResolver;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.ParameterModelFactory;
import de.rwth.swc.coffee4j.model.InputParameterModel;
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
        derivationContainer = new DerivationContainer(argAccessor.toList());
        Config preparedConfig = getConfig();
        derivationContainer.applyToConfig(preparedConfig, context);
        runner.setPreparedConfig(preparedConfig);
        runner.setDerivationContainer(derivationContainer);
        return preparedConfig;
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

