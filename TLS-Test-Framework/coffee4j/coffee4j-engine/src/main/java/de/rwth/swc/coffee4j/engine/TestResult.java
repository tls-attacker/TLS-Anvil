package de.rwth.swc.coffee4j.engine;

import java.util.Objects;
import java.util.Optional;

/**
 * Specifies the result of a test. Either a test threw no exception and was therefore successful, or it has an
 * exception as a cause for failure.
 */
public final class TestResult {
    
    private final Throwable causeForFailure;
    
    /**
     * Creates a new result for a successful test.
     */
    public TestResult() {
        this(null);
    }
    
    /**
     * Creates a new result for a successful test if the exception is {@code null}, or a failed test otherwise.
     *
     * @param causeForFailure the exception which caused the failure
     */
    public TestResult(Throwable causeForFailure) {
        this.causeForFailure = causeForFailure;
    }
    
    /**
     * Descriptive convenience method for constructing a result for a successful test input.
     *
     * @return a successful result
     */
    public static TestResult success() {
        return new TestResult();
    }
    
    /**
     * Descriptive convenience method for constructing a result for a failed test input.
     *
     * @param causeForFailure the exception which caused the test to fail, or indicates that it has failed
     * @return a failed result
     */
    public static TestResult failure(Throwable causeForFailure) {
        return new TestResult(causeForFailure);
    }
    
    /**
     * @return whether the result indicates success (no exception given)
     */
    public boolean isSuccessful() {
        return causeForFailure == null;
    }
    
    /**
     * @return whether the result indicates failure (exception given)
     */
    public boolean isUnsuccessful() {
        return causeForFailure != null;
    }
    
    /**
     * @return an optional containing the exception which caused the failure or an empty optional if the test was
     * successful
     */
    public Optional<Throwable> getCauseForFailure() {
        return Optional.ofNullable(causeForFailure);
    }
    
    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        
        final TestResult other = (TestResult) object;
        return Objects.equals(causeForFailure, other.causeForFailure);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(causeForFailure);
    }
    
    @Override
    public String toString() {
        if (causeForFailure == null) {
            return "TestResult{success}";
        } else {
            return "TestResult{failure, cause=" + causeForFailure + "}";
        }
    }
    
}
