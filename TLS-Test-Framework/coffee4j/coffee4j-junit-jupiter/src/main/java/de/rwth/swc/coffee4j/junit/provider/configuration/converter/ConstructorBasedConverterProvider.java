package de.rwth.swc.coffee4j.junit.provider.configuration.converter;

import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumer;
import org.junit.platform.commons.JUnitException;

import java.util.ArrayList;
import java.util.List;

class ConstructorBasedConverterProvider implements ConverterProvider, AnnotationConsumer<Converter> {

    private Class<? extends ArgumentConverter>[] converterClasses;

    @Override
    public void accept(Converter converter) {
        converterClasses = converter.value();
    }

    @Override
    public List<ArgumentConverter> provide(ExtensionContext extensionContext) {
        final List<ArgumentConverter> generators = new ArrayList<>();

        for (Class<? extends ArgumentConverter> converterClass : converterClasses) {
            generators.add(createConverterInstance(converterClass));
        }

        return generators;
    }

    private ArgumentConverter createConverterInstance(Class<? extends ArgumentConverter> converterClass) {
        try {
            return converterClass.getConstructor().newInstance();
        } catch (Exception e) {
            final String message = "Could not create a new instance of " + converterClass.getSimpleName() + " with a default constructor";
            throw new JUnitException(message, e);
        }
    }

}
