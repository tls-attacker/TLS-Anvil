package de.rwth.swc.coffee4j.junit.provider.model;

import de.rwth.swc.coffee4j.model.InputParameterModel;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumer;
import org.junit.platform.commons.JUnitException;

import static de.rwth.swc.coffee4j.junit.provider.ProviderUtil.getObjectReturnedByMethod;

/**
 * A provider loading a class from a method as described in {@link ModelFromMethod}.
 * <p>
 * This is a more or less direct copy of org.junit.jupiter.params.provider.MethodArgumentsProvider from the
 * junit-jupiter-params project.
 */
public class MethodBasedProvider implements ModelProvider, AnnotationConsumer<ModelFromMethod> {
    
    private String methodName;
    
    @Override
    public void accept(ModelFromMethod modelFromMethod) {
        methodName = modelFromMethod.value();
    }
    
    @Override
    public InputParameterModel provide(ExtensionContext extensionContext) {
        final Object providedObject = getObjectReturnedByMethod(extensionContext, methodName);
        return toInputParameterModel(providedObject);
    }
    
    private static InputParameterModel toInputParameterModel(Object object) {
        if (object instanceof InputParameterModel) {
            return (InputParameterModel) object;
        } else if (object instanceof InputParameterModel.Builder) {
            return ((InputParameterModel.Builder) object).build();
        } else {
            throw new JUnitException("The given method must either return an " + InputParameterModel.class.getName() + " or an " + InputParameterModel.Builder.class.getName() + ". Instead a " + object.getClass().getName() + " was returned");
        }
    }
    
}
