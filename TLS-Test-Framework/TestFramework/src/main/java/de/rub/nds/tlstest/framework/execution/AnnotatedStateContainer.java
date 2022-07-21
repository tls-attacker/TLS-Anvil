/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.execution;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.reporting.ScoreContainer;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import de.rub.nds.tlstest.framework.utils.Utils;
import de.rwth.swc.coffee4j.model.Combination;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;


/**
 * Usually each test case performing a handshake is associated with a AnnotatedStateContainer.
 * This class contains a list of States / Handshakes that are the result
 * of the derivation process.
 */
public class  AnnotatedStateContainer {
    private static final Logger LOGGER = LogManager.getLogger();
    private boolean finished = false;
    private final long startTime = System.currentTimeMillis();
    private int resultRaw = 0;
    private String uniqueId;

    @JsonProperty("TestMethod")
    private TestMethodConfig testMethodConfig;

    @JsonProperty("Result")
    private TestResult result;

    @JsonProperty("HasStateWithAdditionalResultInformation")
    private Boolean hasStateWithAdditionalResultInformation = false;
    
    @JsonProperty("HasVaryingAdditionalResultInformation")
    private Boolean hasVaryingAdditionalResultInformation = false;

    @JsonProperty("DisabledReason")
    private String disabledReason;

    @JsonProperty("FailedReason")
    private String failedReason;

    @JsonProperty("ElapsedTime")
    private long elapsedTime = 0;

    @JsonProperty("StatesCount")
    private int statesCount;

    @JsonProperty("FailureInducingCombinations")
    List<DerivationContainer> failureInducingCombinations;

    @JsonProperty("States")
    private List<AnnotatedState> states = new ArrayList<>();

    @JsonUnwrapped
    private ScoreContainer scoreContainer;

    @Override
    public String toString() {
        return String.format("AnnotatedStateContainer{displayName = %s, result = %s}",
                testMethodConfig != null ? testMethodConfig.getClassName() + "." + testMethodConfig.getMethodName() : "null",
                result != null ? result.name() : "null"
        );

    }

    private AnnotatedStateContainer(ExtensionContext extensionContext) {
        this.uniqueId = extensionContext.getUniqueId();
        this.scoreContainer = new ScoreContainer(extensionContext);
    }

    synchronized public static AnnotatedStateContainer forExtensionContext(ExtensionContext extensionContext) {
        ExtensionContext resolvedContext = Utils.getTemplateContainerExtensionContext(extensionContext);

        if (TestContext.getInstance().getTestResult(resolvedContext.getUniqueId()) != null) {
            return TestContext.getInstance().getTestResult(resolvedContext.getUniqueId());
        }

        AnnotatedStateContainer container = new AnnotatedStateContainer(resolvedContext);
        container.setTestMethodConfig(new TestMethodConfig(resolvedContext));
        TestContext.getInstance().addTestResult(container);
        return container;
    }

    public void addAll(List<AnnotatedState> states) {
        states.parallelStream().forEach(i -> i.setAssociatedContainer(this));
        this.states.addAll(states);
    }

    public void addAll(AnnotatedState... states) {
        this.addAll(Arrays.asList(states));
    }

    public void add(AnnotatedState state) {
        state.setAssociatedContainer(this);
        this.states.add(state);
    }

    public void finished() {
        TestContext.getInstance().testFinished(this.uniqueId);
        finished = true;
        elapsedTime = System.currentTimeMillis() - startTime;
        statesCount = states.size();
        List<String> uuids = new ArrayList<>();
        List<Throwable> errors = new ArrayList<>();
        boolean failed = false;
        
        String lastAdditionalResultInformation = "";
        TestContext.getInstance().increasePerformedHandshakes(this.getStates().size());

        for (AnnotatedState state : this.getStates()) {
            if (state.getResult() == TestResult.FULLY_FAILED) {
                errors.add(state.getFailedReason());
                failed = true;
            }

            if (!state.getAdditionalResultInformation().isEmpty()) {
                this.setHasStateWithAdditionalResultInformation((Boolean) true);
                if(!state.getAdditionalResultInformation().equals(lastAdditionalResultInformation)
                        && !lastAdditionalResultInformation.isEmpty()) {
                    this.setHasVaryingAdditionalResultInformation((Boolean) true);
                }
                lastAdditionalResultInformation = state.getAdditionalResultInformation();
            }

            if (uuids.contains(state.getUuid())) {
                LOGGER.warn("uuids of states in container are not unique! ({}.{})", this.testMethodConfig.getClassName(), this.testMethodConfig.getMethodName());
                continue;
            }
            uuids.add(state.getUuid());
        }

        if (failed) {
            for (Throwable i: errors) {
                if (System.getenv("DOCKER") != null) {
                    LOGGER.debug("", i);
                } else {
                    LOGGER.error("", i);
                }
            }
            failedReason = String.format("%d/%d tests failed", errors.size(), states.size());
        }
  
        if(anyStateSucceeded() && failed) {
            LOGGER.info("Some generated inputs resulted in failures for test " + testMethodConfig.getMethodName()); 
            if (failureInducingCombinations != null) {
                String tmp = failureInducingCombinations.stream().map(DerivationContainer::toString).collect(Collectors.joining("\n\t"));
                LOGGER.info("The following parameters resulted in test failures:\n\t{}", tmp);
            } else {
                LOGGER.info("No fault characterization result obtained");
            }
            printFailedContainers();
        } else if(failed) {
            LOGGER.info("All generated inputs resulted in failures for test " + testMethodConfig.getMethodName());
        }
        
        serialize();
    }

    public void stateFinished(TestResult result) {
        setResultRaw(this.resultRaw | result.getValue());
    }
    
    private void printFailedContainers() {
        LOGGER.info("Individual failed Containers for test " + testMethodConfig.getMethodName() +":\n");
        states.stream().filter(state -> state.getResult() != TestResult.STRICTLY_SUCCEEDED)
                .forEach(state -> LOGGER.info(state.getDerivationContainer().toString()));
    }

    public List<AnnotatedState> getStates() {
        return states;
    }

    public void setStates(List<AnnotatedState> states) {
        this.states = states;
    }

    public String getUniqueId() {
        return uniqueId;
    }

    public void setUniqueId(String uniqueId) {
        this.uniqueId = uniqueId;
    }

    public void setResultRaw(int resultRaw) {
        this.resultRaw = resultRaw;
        result = TestResult.resultForBitmask(resultRaw);
        scoreContainer.updateForResult(result);
    }

    public TestResult getResult() {
        return result;
    }

    public TestMethodConfig getTestMethodConfig() {
        return testMethodConfig;
    }

    public void setTestMethodConfig(TestMethodConfig testMethodConfig) {
        this.testMethodConfig = testMethodConfig;
    }

    public String getDisabledReason() {
        return disabledReason;
    }

    public void setDisabledReason(String disabledReason) {
        this.disabledReason = disabledReason;
    }

    public Long getElapsedTime() {
        return elapsedTime;
    }
    
    private boolean anyStateSucceeded() {
        return states.stream().anyMatch(state -> state.getResult() == TestResult.STRICTLY_SUCCEEDED || state.getResult() == TestResult.CONCEPTUALLY_SUCCEEDED);
    }

    public List<DerivationContainer> getFailureInducingCombinations() {
        return failureInducingCombinations;
    }

    public void setFailureInducingCombinations(List<Combination> failureInducingCombinations) {
        if (failureInducingCombinations == null || failureInducingCombinations.isEmpty())
            return;

        List<DerivationContainer> parameters = new ArrayList<>();
        for (Combination i : failureInducingCombinations) {
            DerivationContainer container = DerivationContainer.fromCombination(i);
            parameters.add(container);
        }

        this.failureInducingCombinations = parameters;
    }

    public ScoreContainer getScoreContainer() {
        return scoreContainer;
    }

    public String getFailedReason() {
        return failedReason;
    }

    public void setFailedReason(String failedReason) {
        this.failedReason = failedReason;
    }

    public boolean isFinished() {
        return finished;
    }

    public Boolean getHasStateWithAdditionalResultInformation() {
        return hasStateWithAdditionalResultInformation;
    }

    public void setHasStateWithAdditionalResultInformation(Boolean hasStateWithAdditionalResultInformation) {
        this.hasStateWithAdditionalResultInformation = hasStateWithAdditionalResultInformation;
    }

    public Boolean getHasVaryingAdditionalResultInformation() {
        return hasVaryingAdditionalResultInformation;
    }

    public void setHasVaryingAdditionalResultInformation(Boolean hasVaryingAdditionalResultInformation) {
        this.hasVaryingAdditionalResultInformation = hasVaryingAdditionalResultInformation;
    }

    private String getSerializationPath() {
        String method = testMethodConfig.getCompleteMethodName();
        // truncate the class name to shorten the path length
        // basically throw away the common package, i.e. everything before "server" or "client"
        String pName = "de.rub.nds.tlstest.suite.tests.";
        method = method.replace(pName, "");

        String[] folderComponents = method.split("\\.");

        return Paths.get(TestContext.getInstance().getConfig().getOutputFolder(), folderComponents).toString();
    }

    private void serialize() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker()
                .withFieldVisibility(JsonAutoDetect.Visibility.NONE)
                .withGetterVisibility(JsonAutoDetect.Visibility.NONE)
                .withSetterVisibility(JsonAutoDetect.Visibility.NONE)
                .withCreatorVisibility(JsonAutoDetect.Visibility.NONE));

        if (TestContext.getInstance().getConfig().isPrettyPrintJSON()) {
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
        }

        String targetFolder = getSerializationPath();

        String containerResultPath = Paths.get(targetFolder, "_containerResult.json").toString();
        File f = new File(containerResultPath);
        StringBuilder errorMsg = new StringBuilder();
        Utils.createEmptyFile(containerResultPath);

        try {
            mapper.writeValue(f, this);
        } catch (Exception e) {
            LOGGER.error("Failed to serialize AnnotatedStateContainer ({})", testMethodConfig.getCompleteMethodName(), e);
            errorMsg.append("Failed to serialize AnnotatedStateContainer\n");
            errorMsg.append(ExecptionPrinter.stacktraceToString(e));
        }
        
        if(TestContext.getInstance().getConfig().isExportTraces()) {
            try {
                FileOutputStream fos = new FileOutputStream(Paths.get(targetFolder, "traces.zip").toString());
                ZipOutputStream zipOut = new ZipOutputStream(fos);
                for (AnnotatedState s : states) {
                    ZipEntry zipEntry = new ZipEntry(s.getUuid() + ".xml");
                    zipOut.putNextEntry(zipEntry);
                    try {
                        String serialized = WorkflowTraceSerializer.write(s.getWorkflowTrace());
                        zipOut.write(serialized.getBytes(StandardCharsets.UTF_8));
                    } catch (Exception e) {
                        LOGGER.error("Failed to serialize State ({}, {})", testMethodConfig.getCompleteMethodName(), s.getUuid(), e);
                        errorMsg.append("\nFailed to serialize WorkflowTraces");
                        errorMsg.append(ExecptionPrinter.stacktraceToString(e));
                    }
                }   
                zipOut.close();
                fos.close();
            } catch (Exception e){
                LOGGER.error("", e);
            }
        }
        try {
            String err = errorMsg.toString();
            if (!err.isEmpty()) {
                FileWriter fileWriter = new FileWriter(Paths.get(targetFolder, "_error.txt").toString());
                PrintWriter printWriter = new PrintWriter(fileWriter);
                printWriter.print(err);
                printWriter.close();
            }
        } catch (Exception ignored) {}

    }
}
