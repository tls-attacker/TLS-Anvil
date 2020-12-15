package de.rwth.swc.coffee4j.junit.provider.configuration;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.ExtensionContextBasedProvider;
import de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManagerConfiguration;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * An {@code ConfigurationProvider} is responsible for {@linkplain #provide(ExtensionContext) providing} exactly one
 * {@link CombinatorialTestConsumerManagerConfiguration} for use in a
 * {@link CombinatorialTest}.
 * <p>
 * To register a {@link ConfigurationProvider}, use the {@link ConfigurationSource} annotation as demonstrated by
 * {@link ConfigurationFromMethod}.
 * <p>
 * Implementations must provide a no-args constructor.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.provider.ArgumentsProvider} from the
 * junit-jupiter-params project.
 */
@FunctionalInterface
public interface ConfigurationProvider extends ExtensionContextBasedProvider<CombinatorialTestConsumerManagerConfiguration> {
}
