/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.reporting;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Score {
    private static final Logger LOGGER = LogManager.getLogger();

    @JsonProperty("Reached")
    private double reached = 0;

    @JsonProperty("Total")
    private double total = 0;

    @JsonProperty("SeverityLevel")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private SeverityLevel severityLevel;

    private int max = 100;

    private boolean overwritten = false;

    public Score() {
        super();
    }

    public Score(SeverityLevel level) {
        this(0, level.getMaxScore());
        this.severityLevel = level;
    }

    public Score(double reached, double total) {
        super();
        this.reached = reached;
        this.total = total;
    }

    public double getTotal() {
        return total;
    }

    public void setTotal(double total) {
        this.total = total;
    }

    public double getReached() {
        return reached;
    }

    public void setReached(double reached) {
        this.reached = reached;
    }

    @JsonProperty("Percentage")
    public double getPercentage() {
        if (total == 0) return 100;
        return reached / total * 100;
    }

    public SeverityLevel getSeverityLevel() {
        return severityLevel;
    }

    public void setSeverityLevel(SeverityLevel severityLevel) {
        this.severityLevel = severityLevel;
    }

    public int getMax() {
        return max;
    }

    public void setMax(int max) {
        if (max > 100) {
            LOGGER.error(
                    "max is given in percentage, a value larger than 100 does not make sense.");
            return;
        }
        this.max = max;
    }

    public void updateForTestResult(TestResult result) {
        if (overwritten) return;
        if (result == TestResult.DISABLED) {
            setReached(0);
            setTotal(0);
            return;
        }
        setReached(
                (result.getScorePercentage() / 100.0)
                        * severityLevel.getMaxScore()
                        * (max / 100.0));
    }

    public void overwiteTestResult(TestResult status) {
        overwritten = true;
        setReached(
                (status.getScorePercentage() / 100.0)
                        * severityLevel.getMaxScore()
                        * (max / 100.0));
    }

    public boolean isOverwritten() {
        return overwritten;
    }

    public void setOverwritten(boolean overwritten) {
        this.overwritten = overwritten;
    }
}
