package de.rwth.swc.coffee4j.model;

import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import it.unimi.dsi.fastutil.ints.IntSet;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Represents a parameter form an input parameter testModel for combinatorial testing. As such it has a descriptive and
 * unique name (at least unique inside its input parameter testModel), and a list of arbitrary many values.
 */
public final class Parameter {
    
    private final String name;
    private final List<Value> values;
    
    /**
     * Creates a new parameter with the given name and values.
     *
     * @param name   the parameters name. Should be unique inside its input parameter testModel. Must not be {@code null}
     * @param values the values of the parameter. Must not be, nor contain {@code null}, and there need to be at least
     *               two value. Additionally, each value id may only appear once
     */
    public Parameter(String name, Collection<Value> values) {
        Preconditions.notNull(name);
        Preconditions.notNull(values);
        Preconditions.check(values.size() >= 2);
        Preconditions.doesNotContainNull(values);
        Preconditions.check(doesNotContainSameValueIdTwice(values));
        
        this.name = name;
        this.values = new ArrayList<>(values);
    }
    
    private static boolean doesNotContainSameValueIdTwice(Collection<Value> values) {
        final IntSet valueIds = new IntOpenHashSet(values.size());
        
        for (Value value : values) {
            if (valueIds.contains(value.getId())) {
                return false;
            }
            valueIds.add(value.getId());
        }
        
        return true;
    }
    
    /**
     * @return the name of the parameter. Should be unique inside its input parameter testModel
     */
    public String getName() {
        return name;
    }
    
    /**
     * @return all values of this parameter
     */
    public List<Value> getValues() {
        return Collections.unmodifiableList(values);
    }
    
    /**
     * @return the number of values this parameter has
     */
    public int size() {
        return values.size();
    }
    
    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        
        final Parameter other = (Parameter) object;
        return Objects.equals(name, other.name) && Objects.equals(values, other.values);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(name, values);
    }
    
    @Override
    public String toString() {
        return "Parameter{" + "name='" + name + '\'' + ", values=" + values + '}';
    }
    
    public static Builder parameter(String name) {
        return new Builder(name);
    }
    
    /**
     * Realizes the builder pattern for a {@link Parameter}. Starting point is {@link #parameter(String)}.
     */
    public static final class Builder {
        
        private final String name;
        
        private final List<Value> values = new ArrayList<>();
        
        private Builder(String name) {
            this.name = name;
        }
        
        /**
         * Adds on new value to the parameter. The value will have the number of previous values as an id, the the
         * given object as data.
         *
         * @param value the value object to be added. May be {@code null} as it will be wrapped in {@link Value}
         * @return this
         */
        public Builder value(Object value) {
            values.add(new Value(values.size(), value));
            
            return this;
        }
        
        /**
         * Adds all new values to the parameter. The values will have the ids starting at the number of previous
         * values, and the objects as data.
         *
         * @param values the value objects to be added. May be {@code null} each as they will be wrapped
         *               in {@link Value}
         * @return this
         */
        public Builder values(Object... values) {
            Preconditions.notNull(values);
            
            for (Object value : values) {
                value(value);
            }
            
            return this;
        }
        
        /**
         * Builds a new parameter. If less than two values were added, this will throw an exception.
         *
         * @return the constructed parameter
         */
        public Parameter build() {
            return new Parameter(name, values);
        }
        
    }
    
}
