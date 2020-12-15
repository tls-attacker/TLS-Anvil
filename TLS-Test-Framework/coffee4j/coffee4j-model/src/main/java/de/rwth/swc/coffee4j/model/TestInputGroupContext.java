package de.rwth.swc.coffee4j.model;

import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;

import java.util.Objects;

/**
 * A class representing a {@link TestInputGroup} to the outside. This does not
 * contain test inputs but therefore the {@link TestInputGroupGenerator} used to generate the group.
 * It is used for identification in {@link ExecutionReporter}.
 */
public final class TestInputGroupContext {
    
    private final Object identifier;
    
    private final TestInputGroupGenerator generator;
    
    /**
     * Creates a new context with the given identifier and generator.
     *
     * @param identifier a unique identifier of this test input group
     * @param generator  the generator used to generate the test input group
     */
    public TestInputGroupContext(Object identifier, TestInputGroupGenerator generator) {
        this.identifier = Preconditions.notNull(identifier);
        this.generator = Preconditions.notNull(generator);
    }
    
    /**
     * @return the unique identifier
     */
    public Object getIdentifier() {
        return identifier;
    }
    
    /**
     * @return the generator used to generate the test input group
     */
    public TestInputGroupGenerator getGenerator() {
        return generator;
    }
    
    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        
        final TestInputGroupContext other = (TestInputGroupContext) object;
        return Objects.equals(identifier, other.identifier) && Objects.equals(generator, other.generator);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(identifier, generator);
    }
    
    @Override
    public String toString() {
        return "TestInputGroupContext{" + "identifier='" + identifier + '\'' + ", generator=" + generator + '}';
    }
    
}
