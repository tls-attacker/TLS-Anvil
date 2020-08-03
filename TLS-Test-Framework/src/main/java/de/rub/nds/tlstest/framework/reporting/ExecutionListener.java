package de.rub.nds.tlstest.framework.reporting;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.reporting.ReportEntry;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExecutionListener implements TestExecutionListener {
    private static final Logger LOGGER = LogManager.getLogger();

    private long start;

    private Map<String, Long> testElapsedTimes = new HashMap<>();
    private Map<String, Long> containerElapsedTimes = new HashMap<>();

    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        start = System.currentTimeMillis();
        LOGGER.trace(testPlan.toString() + " started");
    }

    @Override
    public void testPlanExecutionFinished(TestPlan testPlan) {
        LOGGER.trace(testPlan.toString() + " finished");
        long elapsedTime = System.currentTimeMillis() - start;

        Set<TestIdentifier> roots = testPlan.getRoots();
        List<TestResultContainer> rootContainers = new ArrayList<>();

        for (TestIdentifier rootIdentifier: roots) {
            Set<TestIdentifier> identifiers = testPlan.getDescendants(rootIdentifier);
            if (identifiers.size() == 0) continue;

            TestResultContainer root = new TestResultContainer(rootIdentifier);
            root.setElapsedTime(elapsedTime);
            root.setTestEndpointType(TestContext.getInstance().getConfig().getTestEndpointMode());
            root.setIdentifier(TestContext.getInstance().getConfig().getIdentifier());
            root.setDate(TestContext.getInstance().getStartTime());
            rootContainers.add(root);

            Set<TestIdentifier> containers = new HashSet<>(identifiers);
            containers.removeIf(i -> !i.isContainer());
            for (TestIdentifier container : containers) {
                TestResultContainer child = root.addChildContainer(container);
                child.setElapsedTime(containerElapsedTimes.get(container.getUniqueId()));
            }

            Set<TestIdentifier> tests = new HashSet<>(identifiers);
            Map<String, AnnotatedStateContainer> results = TestContext.getInstance().getTestResults();
            tests.removeIf(i -> !i.isTest());
            for (TestIdentifier i : tests) {
                if (!i.getParentId().isPresent()) {
                    throw new RuntimeException("Test has no parent...");
                }
                root.addResultWithParent(i.getParentId().get(), results.get(i.getUniqueId()));
            }
        }

        if (TestContext.getInstance().getConfig().getOutputFormat().equals("json")) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker()
                        .withFieldVisibility(JsonAutoDetect.Visibility.NONE)
                        .withGetterVisibility(JsonAutoDetect.Visibility.NONE)
                        .withSetterVisibility(JsonAutoDetect.Visibility.NONE)
                        .withCreatorVisibility(JsonAutoDetect.Visibility.NONE));

                File f = new File(TestContext.getInstance().getConfig().getOutputFile());
                f.getParentFile().mkdirs();
                f.createNewFile();

                mapper.writeValue(new File(TestContext.getInstance().getConfig().getOutputFile()), rootContainers.get(0));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }
        else {
            try {
                JAXBContext jaxbContext = JAXBContext.newInstance(TestResultContainer.class);
                Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
                jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

                File f = new File(TestContext.getInstance().getConfig().getOutputFile());
                f.getParentFile().mkdirs();
                jaxbMarshaller.marshal(rootContainers.get(0), f);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

    }

    @Override
    public void executionSkipped(TestIdentifier testIdentifier, String reason) {
        LOGGER.trace(testIdentifier.getDisplayName() + " skipped, due to " + reason);
    }

    @Override
    public void executionStarted(TestIdentifier testIdentifier) {
        LOGGER.trace(testIdentifier.getDisplayName() + " started");
        if (testIdentifier.isTest()) {
            testElapsedTimes.put(testIdentifier.getUniqueId(), System.currentTimeMillis());
        } else if (testIdentifier.isContainer()) {
            containerElapsedTimes.put(testIdentifier.getUniqueId(), System.currentTimeMillis());
        }
    }

    @Override
    public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
        LOGGER.trace(testIdentifier.getDisplayName() + " finished");
        if (testIdentifier.isTest()) {
            Long startTime = testElapsedTimes.get(testIdentifier.getUniqueId());
            if (startTime != null) {
                long elapsedTime = System.currentTimeMillis() - startTime;
                AnnotatedStateContainer result = TestContext.getInstance().getTestResults().get(testIdentifier.getUniqueId());
                if (result != null)
                    result.setElapsedTime(elapsedTime);

                testElapsedTimes.remove(testIdentifier.getUniqueId());
            }
        } else if (testIdentifier.isContainer()) {
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
