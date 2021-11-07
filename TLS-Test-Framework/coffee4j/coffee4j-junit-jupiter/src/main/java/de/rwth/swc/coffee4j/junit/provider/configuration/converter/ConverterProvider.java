package de.rwth.swc.coffee4j.junit.provider.configuration.converter;

import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.ExtensionContextBasedProvider;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Collection;

/**
 * An {@code ConverterProvider} is responsible for {@linkplain #provide(ExtensionContext) providing}
 * exactly an arbitrary number of {@link ArgumentConverter} implementations (even none is allowed) for a
 * {@link CombinatorialTest}.
 * <p>
 * To register a {@link ConverterProvider}, use the {@link ConverterSource}
 * annotation as demonstrated by {@link Converter}.
 * <p>
 * Implementations must provide a no-args constructor.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.provider.ArgumentsProvider} from the
 * junit-jupiter-params project.
 */
@FunctionalInterface
public interface ConverterProvider extends ExtensionContextBasedProvider<Collection<ArgumentConverter>> {
}
