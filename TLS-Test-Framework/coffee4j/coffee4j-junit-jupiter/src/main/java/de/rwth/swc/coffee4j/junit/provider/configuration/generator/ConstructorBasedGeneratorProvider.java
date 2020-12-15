package de.rwth.swc.coffee4j.junit.provider.configuration.generator;

import de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumer;
import org.junit.platform.commons.JUnitException;

import java.util.ArrayList;
import java.util.List;

class ConstructorBasedGeneratorProvider implements GeneratorProvider, AnnotationConsumer<Generator> {
    
    private Class<? extends TestInputGroupGenerator>[] generatorClasses;
    private Class<? extends ConstraintCheckerFactory>[] factoryClasses;

    @Override
    public void accept(Generator generatorSource) {
        Preconditions.check(generatorSource.algorithms().length == generatorSource.factories().length);

        generatorClasses = Preconditions.notNull(generatorSource.algorithms());
        factoryClasses = Preconditions.notNull(generatorSource.factories());
    }
    
    @Override
    public List<TestInputGroupGenerator> provide(ExtensionContext extensionContext) {
        final List<TestInputGroupGenerator> generators = new ArrayList<>();

        for(int i = 0; i < generatorClasses.length; i++) {
            final Class<? extends TestInputGroupGenerator> generatorClass = generatorClasses[i];
            final Class<? extends ConstraintCheckerFactory> factoryClass = factoryClasses[i];

            final ConstraintCheckerFactory factory = createConstraintCheckerFactory(factoryClass);

            generators.add(createGeneratorInstance(generatorClass, factory));
        }

        return generators;
    }

    private ConstraintCheckerFactory createConstraintCheckerFactory(Class<? extends ConstraintCheckerFactory> factoryClass) {
        try {
            return factoryClass.getConstructor().newInstance();
        } catch (Exception e) {
            final String message = "Could not create a new instance of "
                    + factoryClass.getSimpleName()
                    + " with default constructor";

            throw new JUnitException(message, e);
        }
    }

    private TestInputGroupGenerator createGeneratorInstance(Class<? extends TestInputGroupGenerator> generatorClass,
                                                            ConstraintCheckerFactory factory) {
        try {
            return generatorClass
                    .getConstructor(ConstraintCheckerFactory.class)
                    .newInstance(factory);

        } catch (Exception e) {
            final String message = "Could not create a new instance of "
                    + generatorClass.getSimpleName()
                    + " with a default constructor";

            throw new JUnitException(message, e);
        }
    }
}
