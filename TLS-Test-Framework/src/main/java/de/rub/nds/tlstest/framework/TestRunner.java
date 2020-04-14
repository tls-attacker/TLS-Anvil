package de.rub.nds.tlstest.framework;

import de.rub.nds.tlstest.framework.config.TestConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TagFilter;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;

import java.io.PrintWriter;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;

public class TestRunner {
    private static final Logger LOGGER = LogManager.getLogger();

    private TestConfig testConfig;

    public TestRunner(TestConfig testConfig) {
        this.testConfig = testConfig;
    }

    public void runTests(Class<?> mainClass) {
        String packageName = mainClass.getPackage().getName();
        LauncherDiscoveryRequestBuilder builder = LauncherDiscoveryRequestBuilder.request()
            .selectors(
                    selectPackage(packageName)
            );


        if (testConfig.getTags().size() > 0) {
            builder.filters(
                    TagFilter.includeTags(testConfig.getTags())
            );
        }

        LauncherDiscoveryRequest request = builder.build();

        Launcher launcher = LauncherFactory.create();

        SummaryGeneratingListener listener = new SummaryGeneratingListener();
        launcher.registerTestExecutionListeners(listener);

        launcher.execute(request);

        TestExecutionSummary summary = listener.getSummary();
        summary.printTo(new PrintWriter(System.out));
    }
}
