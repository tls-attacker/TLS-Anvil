package de.rwth.swc.coffee4j.junit.provider.model;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.ExtensionContextBasedProvider;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * An {@code ModelProvider} is responsible for {@linkplain #provide(ExtensionContext) providing} exactly one
 * {@link InputParameterModel} for use in a {@link CombinatorialTest}.
 * <p>
 * To register a {@link ModelProvider}, use the {@link ModelSource} annotation as demonstrated by
 * {@link ModelFromMethod}.
 * <p>
 * Implementations must provide a no-args constructor.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.provider.ArgumentsProvider} from the
 * junit-jupiter-params project.
 */
@FunctionalInterface
public interface ModelProvider extends ExtensionContextBasedProvider<InputParameterModel> {
}
