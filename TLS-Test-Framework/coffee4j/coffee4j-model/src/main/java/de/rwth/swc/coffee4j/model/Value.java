package de.rwth.swc.coffee4j.model;

import java.util.Objects;

/**
 * Represents a value for a input parameter testModel in combinatorial testing. One could say that this class is not really
 * needed as it just wraps an object, but it gives the additional distinction between this value object being
 * {@code null} and no object being present. The id field is need for quicker comparison in {@link #hashCode()}
 * and {@link #equals(Object)} and is only valid when comparing values inside one {@link Parameter}.
 */
public final class Value {
    
    private final int id;
    
    private final Object data;
    
    /**
     * Creates a new value with the given id and object
     *
     * @param id   an id which should be unique inside the values parameter
     * @param data the data value to be saved. Can be {@code null}
     */
    public Value(int id, Object data) {
        this.id = id;
        this.data = data;
    }
    
    /**
     * @return the values id which is unique only inside its parameter
     */
    public int getId() {
        return id;
    }
    
    /**
     * @return the actual value. May be {@code null}
     */
    public Object get() {
        return data;
    }
    
    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        
        final Value other = (Value) object;
        return Objects.equals(id, other.id);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
    
    @Override
    public String toString() {
        return data == null ? "null" : data.toString();
    }
    
    /**
     * Convenience method which can be statically imported for easier and more readable code.
     *
     * @param id   an id which should be unique inside the values parameter
     * @param data the data value to be saved. Can be {@code null}
     * @return a value with the given id and data
     */
    public static Value value(int id, Object data) {
        return new Value(id, data);
    }
    
}
