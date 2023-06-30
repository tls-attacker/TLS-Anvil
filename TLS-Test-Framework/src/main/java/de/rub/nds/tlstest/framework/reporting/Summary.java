/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.reporting;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import java.util.Date;

public class Summary {
    @JsonProperty("ElapsedTime")
    private long elapsedTime;

    @JsonProperty("Identifier")
    private String identifier;

    @JsonProperty("StatesCount")
    private long handshakes;

    @JsonProperty("Date")
    private Date date;

    @JsonProperty("TestEndpointType")
    private TestEndpointType testEndpointType;

    @JsonProperty("SucceededTests")
    private long testsSucceeded;

    @JsonProperty("DisabledTests")
    private long testsDisabled;

    @JsonProperty("FailedTests")
    private long testsFailed;

    @JsonUnwrapped private ScoreContainer scoreContainer;

    public long getElapsedTime() {
        return elapsedTime;
    }

    public void setElapsedTime(long elapsedTime) {
        this.elapsedTime = elapsedTime;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public long getHandshakes() {
        return handshakes;
    }

    public void setHandshakes(long handshakes) {
        this.handshakes = handshakes;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    public long getTestsSucceeded() {
        return testsSucceeded;
    }

    public void setTestsSucceeded(long testsSucceeded) {
        this.testsSucceeded = testsSucceeded;
    }

    public long getTestsFailed() {
        return testsFailed;
    }

    public void setTestsFailed(long testsFailed) {
        this.testsFailed = testsFailed;
    }

    public long getTestsDisabled() {
        return testsDisabled;
    }

    public void setTestsDisabled(long testsDisabled) {
        this.testsDisabled = testsDisabled;
    }

    public TestEndpointType getTestEndpointType() {
        return testEndpointType;
    }

    public void setTestEndpointType(TestEndpointType testEndpointType) {
        this.testEndpointType = testEndpointType;
    }

    public ScoreContainer getScoreContainer() {
        return scoreContainer;
    }

    public void setScoreContainer(ScoreContainer scoreContainer) {
        this.scoreContainer = scoreContainer;
    }
}
