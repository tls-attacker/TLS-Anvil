/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.testClasses;

import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.junit.AnvilTestBaseClass;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.anvil.TlsParameterCombination;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.junitExtensions.EnforcedSenderRestrictionConditionExtension;
import de.rub.nds.tlstest.framework.junitExtensions.KexCondition;
import de.rub.nds.tlstest.framework.junitExtensions.TlsVersionCondition;
import de.rub.nds.tlstest.framework.junitExtensions.WorkflowRunnerResolver;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;

@ExtendWith({
    TlsVersionCondition.class,
    KexCondition.class,
    EnforcedSenderRestrictionConditionExtension.class,
    WorkflowRunnerResolver.class
})
@ModelFromScope(modelType = "GENERIC")
public abstract class TlsBaseTest extends AnvilTestBaseClass {
    protected static final Logger LOGGER = LogManager.getLogger();

    protected TestContext context;

    protected TlsParameterCombination parameterCombination;

    protected ExtensionContext extensionContext;

    @BeforeEach
    public void setExtensionContext(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }

    public Config getPreparedConfig(WorkflowRunner runner) {
        Config toPrepare = getConfig();
        return prepareConfig(toPrepare, runner);
    }

    public Config prepareConfig(Config config, WorkflowRunner runner) {
        AnvilTestCase testCase = AnvilTestCase.fromExtensionContext(extensionContext);
        parameterCombination =
                new TlsParameterCombination(
                        testCase.getParameterCombination().getParameterValues(),
                        testCase.getParameterCombination().getDerivationScope());
        parameterCombination.applyToConfig(config);
        runner.setPreparedConfig(config);
        runner.setTlsParameterCombination(parameterCombination);
        return config;
    }

    public void adjustPreSharedKeyModes(Config config) {
        if (context.getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE)
                        == TestResults.TRUE
                && context.getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK)
                        == TestResults.FALSE) {
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
