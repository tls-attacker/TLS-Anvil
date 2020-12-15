package de.rwth.swc.coffee4j.junit.provider.model;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.Loader;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumerInitializer;
import org.junit.platform.commons.JUnitException;
import org.junit.platform.commons.util.ReflectionUtils;

import java.lang.reflect.Method;

import static org.junit.platform.commons.util.AnnotationUtils.findAnnotation;

/**
 * Class for loading the defined testModel for a {@link CombinatorialTest}.
 * Exactly one annotation of {@link ModelSource} is needed for this to find. Since {@link ModelSource} is inherited,
 * any inheriting annotation such as {@link ModelFromMethod} can also be found by this loader.
 */
public class ModelLoader implements Loader<InputParameterModel> {
    
    @Override
    public InputParameterModel load(ExtensionContext extensionContext) {
        final Method testMethod = extensionContext.getRequiredTestMethod();
        
        final InputParameterModel model = findAnnotation(testMethod, ModelSource.class).map(ModelSource::value).map(ReflectionUtils::newInstance).map(provider -> AnnotationConsumerInitializer.initialize(testMethod, provider)).map(provider -> provider.provide(extensionContext)).orElse(null);
        
        if (model == null) {
            throw new JUnitException("A testModel has to be provided for a combinatorial test");
        }
        
        return model;
    }
    
}
