package de.rub.nds.tlstest.framework.reporting;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;

import java.util.Date;



public class Summary {
    @JsonProperty
    private long elapsedTime;
    @JsonProperty
    private String identifier;
    @JsonProperty
    private long handshakes;
    @JsonProperty
    private Date date;
    @JsonProperty
    private TestEndpointType testEndpointType;

    @JsonProperty
    private long testsSucceeded;
    @JsonProperty
    private long testsDisabled;
    @JsonProperty
    private long testsFailed;

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
}
