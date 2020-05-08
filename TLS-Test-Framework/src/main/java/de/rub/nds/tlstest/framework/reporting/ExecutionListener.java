package de.rub.nds.tlstest.framework.reporting;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestStatus;
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
import java.io.StringWriter;
import java.util.*;

public class ExecutionListener implements TestExecutionListener {
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        LOGGER.info(testPlan.toString() + " started");
    }

    @Override
    public void testPlanExecutionFinished(TestPlan testPlan) {
        LOGGER.info(testPlan.toString() + " finished");

        Set<TestIdentifier> roots = testPlan.getRoots();
        List<TestResultContainer> rootContainers = new ArrayList<>();

        for (TestIdentifier rootIdentifier: roots) {
            Set<TestIdentifier> identifiers = testPlan.getDescendants(rootIdentifier);
            if (identifiers.size() == 0) continue;

            TestResultContainer root = new TestResultContainer(rootIdentifier);
            rootContainers.add(root);

            Set<TestIdentifier> containers = new HashSet<>(identifiers);
            containers.removeIf(i -> !i.isContainer());
            for (TestIdentifier container : containers) {
                root.addChildContainer(container);
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
        String uid = testIdentifier.getUniqueId();
        AnnotatedStateContainer result = new AnnotatedStateContainer();
        result.setStatus(TestStatus.DISABLED);
        result.setReason(reason);
        result.setUniqueId(uid);
        TestContext.getInstance().addTestResult(result);
    }

    @Override
    public void executionStarted(TestIdentifier testIdentifier) {
        LOGGER.info(testIdentifier.getDisplayName() + " started");
    }

    @Override
    public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
        LOGGER.info(testIdentifier.getDisplayName() + " finished");
    }

    @Override
    public void reportingEntryPublished(TestIdentifier testIdentifier, ReportEntry entry) {

    }
}
