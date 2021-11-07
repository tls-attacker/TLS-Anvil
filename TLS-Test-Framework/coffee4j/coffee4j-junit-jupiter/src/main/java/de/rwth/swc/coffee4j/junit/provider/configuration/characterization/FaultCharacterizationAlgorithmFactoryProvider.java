package de.rwth.swc.coffee4j.junit.provider.configuration.characterization;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmFactory;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.ExtensionContextBasedProvider;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * An {@code FaultCharacterizationAlgorithmFactoryProvider} is responsible for {@linkplain #provide(ExtensionContext) providing}
 * exactly one{@link FaultCharacterizationAlgorithmFactory} for use in a
 * {@link CombinatorialTest}.
 * <p>
 * To register a {@link FaultCharacterizationAlgorithmFactoryProvider}, use the {@link FaultCharacterizationAlgorithmFactorySource}
 * annotation as demonstrated by {@link EnableFaultCharacterization}.
 * <p>
 * Implementations must provide a no-args constructor.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.provider.ArgumentsProvider} from the
 * junit-jupiter-params project.
 */
@FunctionalInterface
public interface FaultCharacterizationAlgorithmFactoryProvider extends ExtensionContextBasedProvider<FaultCharacterizationAlgorithmFactory> {
}
