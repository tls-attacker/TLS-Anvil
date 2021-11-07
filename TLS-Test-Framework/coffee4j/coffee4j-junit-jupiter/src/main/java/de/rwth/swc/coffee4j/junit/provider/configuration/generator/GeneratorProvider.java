package de.rwth.swc.coffee4j.junit.provider.configuration.generator;

import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.ExtensionContextBasedProvider;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Collection;

/**
 * An {@code GeneratorProvider} is responsible for {@linkplain #provide(ExtensionContext) providing}
 * an arbitrary number of {@link TestInputGroupGenerator} implementations (even none is allowed) for a
 * {@link CombinatorialTest}.
 * <p>
 * To register a {@link GeneratorProvider}, use the {@link GeneratorSource}
 * annotation as demonstrated by {@link Generator}.
 * <p>
 * Implementations must provide a no-args constructor.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.provider.ArgumentsProvider} from the
 * junit-jupiter-params project.
 */
@FunctionalInterface
public interface GeneratorProvider extends ExtensionContextBasedProvider<Collection<TestInputGroupGenerator>> {
}
