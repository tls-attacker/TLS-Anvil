package de.rwth.swc.coffee4j.junit.provider.configuration.reporter;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.ExtensionContextBasedProvider;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Collection;

/**
 * An {@code ReporterProvider} is responsible for {@linkplain #provide(ExtensionContext) providing}
 * an arbitrary number of {@link ExecutionReporter} implementations (even none is allowed) for a
 * {@link CombinatorialTest}.
 * <p>
 * To register a {@link ReporterProvider}, use the {@link ReporterSource}
 * annotation as demonstrated by {@link Reporter}.
 * <p>
 * Implementations must provide a no-args constructor.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.provider.ArgumentsProvider} from the
 * junit-jupiter-params project.
 */
@FunctionalInterface
public interface ReporterProvider extends ExtensionContextBasedProvider<Collection<ExecutionReporter>> {
}
