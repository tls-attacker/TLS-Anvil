/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.reporting;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import de.rub.nds.tlstest.framework.TestContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.reporting.ReportEntry;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

import java.io.File;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Contains methods that are called when the complete testplan is finished.
 * Generates the test report.
 */
public class ExecutionListener implements TestExecutionListener {
    private static final Logger LOGGER = LogManager.getLogger();

    private long start;

    private Map<String, Long> containerElapsedTimes = new HashMap<>();

    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        start = System.currentTimeMillis();
        LOGGER.trace(testPlan.toString() + " started");
    }

    @Override
    public void testPlanExecutionFinished(TestPlan testPlan) {
        try {
            realTestPlanExecutionFinished(testPlan);
        } catch (Exception e) {
            LOGGER.error("", e);
            throw e;
        }
    }


    private void realTestPlanExecutionFinished(TestPlan testPlan) {
        LOGGER.trace(testPlan.toString() + " finished");
        long elapsedTime = System.currentTimeMillis() - start;
        Summary s = new Summary();

        s.setElapsedTime(elapsedTime);
        s.setTestEndpointType(TestContext.getInstance().getConfig().getTestEndpointMode());
        s.setIdentifier(TestContext.getInstance().getConfig().getIdentifier());
        s.setDate(TestContext.getInstance().getStartTime());
        s.setHandshakes(TestContext.getInstance().getPerformedHandshakes());
        s.setTestsDisabled(TestContext.getInstance().getTestsDisabled());
        s.setTestsFailed(TestContext.getInstance().getTestsFailed());
        s.setTestsSucceeded(TestContext.getInstance().getTestsSucceeded());

        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker()
                    .withFieldVisibility(JsonAutoDetect.Visibility.NONE)
                    .withGetterVisibility(JsonAutoDetect.Visibility.NONE)
                    .withSetterVisibility(JsonAutoDetect.Visibility.NONE)
                    .withCreatorVisibility(JsonAutoDetect.Visibility.NONE));

            if (TestContext.getInstance().getConfig().isPrettyPrintJSON()) {
                mapper.enable(SerializationFeature.INDENT_OUTPUT);
            }

            String summaryPath = Paths.get(TestContext.getInstance().getConfig().getOutputFolder(), "summary.json").toString();
            File f = new File(summaryPath);
            f.createNewFile();

            mapper.writeValue(f, s);
        } catch (Exception e) {
            LOGGER.error("", e);
            throw new RuntimeException(e);
        }

    }

    @Override
    public void executionSkipped(TestIdentifier testIdentifier, String reason) {
        LOGGER.trace(testIdentifier.getDisplayName() + " skipped, due to " + reason);
    }

    @Override
    public void executionStarted(TestIdentifier testIdentifier) {
        LOGGER.trace(testIdentifier.getDisplayName() + " started");
        if (testIdentifier.isContainer()) {
            containerElapsedTimes.put(testIdentifier.getUniqueId(), System.currentTimeMillis());
        }
    }

    @Override
    public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
        LOGGER.trace(testIdentifier.getDisplayName() + " finished");
        if (testIdentifier.isContainer()) {
            Long startTime = containerElapsedTimes.get(testIdentifier.getUniqueId());
            if (startTime != null) {
                long elapsedTime = System.currentTimeMillis() - startTime;
                containerElapsedTimes.put(testIdentifier.getUniqueId(), elapsedTime);
            }
        }

    }

    @Override
    public void reportingEntryPublished(TestIdentifier testIdentifier, ReportEntry entry) {

    }
}
