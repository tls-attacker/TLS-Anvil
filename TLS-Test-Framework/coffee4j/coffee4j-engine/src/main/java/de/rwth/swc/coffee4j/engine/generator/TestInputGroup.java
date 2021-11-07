package de.rwth.swc.coffee4j.engine.generator;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Class which groups multiple test inputs for combinatorial testing
 * together. For example, this can be used to differentiate between
 * positive and negative testing.
 * Tests with the same {@link FaultCharacterizationConfiguration} should
 * always be in the same test group as this makes applying the fault
 * characterization process less time consuming.
 * If fault characterization should not be used/can not be used for a group
 * of test inputs the {@link FaultCharacterizationConfiguration} must not
 * be present.
 *
 * @see TestInputGroupGenerator
 */
public class TestInputGroup {
    
    private final Object identifier;
    
    private final List<int[]> testInputs;
    
    private final FaultCharacterizationConfiguration faultCharacterizationConfiguration;
    
    /**
     * Creates a new group of combinatorial test inputs without a configuration
     * for fault characterization via a {@link FaultCharacterizationAlgorithm}.
     *
     * @param identifier a name which can be display to describe the test input
     *                   group. Should be short and descriptive. Must not be
     *                   {@code null}
     * @param testInputs the test inputs in this group. In every test input all
     *                   parameters should be set. Otherwise correct behaviour
     *                   cannot be guaranteed. Must not be {@code null} but may
     *                   be empty
     * @throws NullPointerException if one of the arguments is {@code null}
     */
    public TestInputGroup(Object identifier, Collection<int[]> testInputs) {
        this(identifier, testInputs, null);
    }
    
    /**
     * Creates a new group of combinatorial test inputs.
     *
     * @param identifier                         a name which can be display to describe the test input
     *                                           group. Should be short and descriptive. Must not be
     *                                           {@code null}
     * @param testInputs                         the test inputs in this group. In every test input all
     *                                           parameters should be set. Otherwise correct behaviour
     *                                           cannot be guaranteed. Must not be {@code null} but may
     *                                           be empty
     * @param faultCharacterizationConfiguration the configuration for using
     *                                           fault characterization on the test
     *                                           inputs after execution. If no fault
     *                                           characterization should be used this
     *                                           can be {@code null}.
     * @throws NullPointerException if {@code identifier} or {@code testInputs}
     *                              is {@code null}
     */
    public TestInputGroup(Object identifier, Collection<int[]> testInputs, FaultCharacterizationConfiguration faultCharacterizationConfiguration) {
        this.identifier = Preconditions.notNull(identifier);
        this.testInputs = new ArrayList<>(Preconditions.notNull(testInputs));
        this.faultCharacterizationConfiguration = faultCharacterizationConfiguration;
    }
    
    /**
     * @return a short descriptive name for the test inputs in this group which
     * can be display to a user of the framework
     */
    public Object getIdentifier() {
        return identifier;
    }
    
    /**
     * @return all test inputs in this group
     */
    public List<int[]> getTestInputs() {
        return Collections.unmodifiableList(testInputs);
    }
    
    /**
     * @return an empty {@link Optional} if no fault characterization should be used
     * for this group or an {@link Optional} with a configuration if it
     * can be used
     */
    public Optional<FaultCharacterizationConfiguration> getFaultCharacterizationConfiguration() {
        return Optional.ofNullable(faultCharacterizationConfiguration);
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        
        final TestInputGroup that = (TestInputGroup) o;
        return Objects.equals(identifier, that.identifier);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(identifier);
    }
    
    @Override
    public String toString() {
        return "TestInputGroup{" + "identifier=" + identifier + ", testInputs=" + testInputs + ", faultCharacterizationConfiguration=" + faultCharacterizationConfiguration + '}';
    }
    
}
