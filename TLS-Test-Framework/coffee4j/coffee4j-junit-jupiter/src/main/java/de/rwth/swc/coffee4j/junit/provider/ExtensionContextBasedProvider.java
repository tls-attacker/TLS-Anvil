package de.rwth.swc.coffee4j.junit.provider;

import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * A general interface used to mark a provider for a resource. They are most likely used together with source
 * definitions form annotations. For example, {@link de.rwth.swc.coffee4j.junit.provider.model.ModelFromMethod} defines
 * the name of a method from which a {@link de.rwth.swc.coffee4j.model.InputParameterModel} is loaded and
 * {@link de.rwth.swc.coffee4j.junit.provider.model.MethodBasedProvider} then loads the testModel from this method.
 *
 * @param <T> the type provided by the method
 */
@FunctionalInterface
public interface ExtensionContextBasedProvider<T> {
    
    /**
     * Provides the instance of T based on an {@link ExtensionContext}.
     *
     * @param extensionContext the context of the current {@link de.rwth.swc.coffee4j.junit.CombinatorialTest} method.
     *                         Must not be {@code null}
     * @return the provided class
     */
    T provide(ExtensionContext extensionContext);
    
}
