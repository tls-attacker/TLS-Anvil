package de.rwth.swc.coffee4j.engine.report;

/**
 * Defines an interface which can be used to convert arguments to different representation forms.
 * Internally, this is used to convert engine representations to testModel representations (which I should not have written
 * here since engine does not know about testModel, but meh...).
 */
public interface ArgumentConverter {
    
    /**
     * Checks whether the given argument can be converted by this {@link ArgumentConverter}. If {@code true} is returned
     * from this method, the result returned by {@link #convert(Object)} is guaranteed to "make sense". Otherwise,
     * the result is not defined an any {@link Exception} may be thrown.
     *
     * @param argument the argument for which a possible conversion is checked
     * @return whether the argument can be converted using {@link #convert(Object)}
     */
    boolean canConvert(Object argument);
    
    /**
     * Converts the given argument if {@link #canConvert(Object)} returned {@code true}. Otherwise the behaviour is
     * intentionally undefined but is it better to throw an {@link Exception}, since returning a nonsensical could
     * make debugging more complex for a user.
     *
     * @param argument the argument which should be converted
     * @return the converted form of the argument
     */
    Object convert(Object argument);
    
}
