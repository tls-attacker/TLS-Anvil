/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.execution;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.reporting.ScoreContainer;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import de.rub.nds.tlstest.framework.utils.Utils;
import de.rwth.swc.coffee4j.model.Combination;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;


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
        TestContext.getInstance().testFinished();
        finished = true;
        elapsedTime = System.currentTimeMillis() - startTime;
        statesCount = states.size();
        List<String> uuids = new ArrayList<>();
        List<Throwable> errors = new ArrayList<>();
        boolean failed = false;
        
        String lastAdditionalResultInformation = "";
        for (AnnotatedState state : this.getStates()) {
            if (state.getResult() == TestResult.FAILED) {
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
    }

    public void stateFinished(TestResult result) {
        setResultRaw(this.resultRaw | result.getValue());
    }
    
    private void printFailedContainers() {
        LOGGER.info("Individual failed Containers for test " + testMethodConfig.getMethodName() +":\n");
        states.stream().filter(state -> state.getResult() != TestResult.SUCCEEDED)
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
        return states.stream().anyMatch(state -> state.getResult() == TestResult.SUCCEEDED || state.getResult() == TestResult.PARTIALLY_SUCCEEDED);
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
}
