package de.rwth.swc.coffee4j.junit.provider;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.model.ModelLoader;
import de.rwth.swc.coffee4j.junit.provider.model.ModelProvider;
import de.rwth.swc.coffee4j.junit.provider.model.ModelSource;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * This basically defines the same interface as {@link ExtensionContextBasedProvider}. It is used for distinction
 * of providers like {@link ModelProvider} which are used to build a
 * testModel from a {@link ModelSource} and
 * {@link ModelLoader}s which attempt to find any such provider to later
 * define a usable testModel.
 *
 * @param <T> the type of class loaded by this interface
 */
@FunctionalInterface
public interface Loader<T> {
    
    /**
     * Loads a T based on the given extension context.
     *
     * @param extensionContext the context of the current {@link CombinatorialTest} method.
     *                         Must not be {@code null}
     * @return the loaded class
     */
    T load(ExtensionContext extensionContext);
    
}
