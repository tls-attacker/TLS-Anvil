package de.rub.nds.tlstest.framework.coffee4j.junit;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.params.aggregator.AggregateWith;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.params.aggregator.ArgumentsAggregator;
import org.junit.jupiter.params.aggregator.DefaultArgumentsAccessor;
import org.junit.jupiter.params.converter.ArgumentConverter;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.DefaultArgumentConverter;
import org.junit.jupiter.params.support.AnnotationConsumerInitializer;
import org.junit.platform.commons.support.ReflectionSupport;
import org.junit.platform.commons.util.AnnotationUtils;
import org.junit.platform.commons.util.ReflectionUtils;
import org.junit.platform.commons.util.StringUtils;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.stream.IntStream;

import static org.junit.platform.commons.util.AnnotationUtils.isAnnotated;

/**
 * One context for a complete {@link CombinatorialTest}. Handles concrete parameter resolving using
 * {@link ArgumentsAggregator} and {@link ArgumentConverter}.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.ParameterizedTestMethodContext} from the
 * junit-jupiter-params project.
 */
class CombinatorialTestMethodContext {
    
    private final ResolverType[] resolverTypes;
    
    private final Resolver[] resolvers;
    
    private final InputParameterModel model;
    
    private int indexOfFirstAggregator = -1;
    
    CombinatorialTestMethodContext(Method testMethod, InputParameterModel model) {
        Parameter[] parameters = testMethod.getParameters();
        this.resolverTypes = new ResolverType[parameters.length];
        this.resolvers = new Resolver[parameters.length];
        this.model = model;
        
        for (int i = 0; i < parameters.length; i++) {
            if (isAggregator(parameters[i])) {
                if (indexOfFirstAggregator == -1) {
                    indexOfFirstAggregator = i;
                }
                resolverTypes[i] = ResolverType.AGGREGATOR;
            } else {
                resolverTypes[i] = ResolverType.CONVERTER;
            }
        }
    }
    
    static boolean checkAggregatorOrder(Method testMethod) {
        final Parameter[] parameters = testMethod.getParameters();
        
        int indexOfPreviousAggregator = -1;
        for (int i = 0; i < parameters.length; i++) {
            if (isAggregator(parameters[i])) {
                if ((indexOfPreviousAggregator != -1) && (i != indexOfPreviousAggregator + 1)) {
                    return false;
                }
                indexOfPreviousAggregator = i;
            }
        }
        return true;
    }
    
    private static boolean isAggregator(Parameter parameter) {
        return ArgumentsAccessor.class.isAssignableFrom(parameter.getType()) || isAnnotated(parameter, AggregateWith.class);
    }
    
    boolean isAggregator(int parameterIndex) {
        return resolverTypes[parameterIndex] == ResolverType.AGGREGATOR;
    }
    
    int indexOfFirstAggregator() {
        return indexOfFirstAggregator;
    }
    
    Object resolve(ParameterContext parameterContext, Combination testInput) {
        final int index = parameterContext.getIndex();
        if (resolvers[index] == null) {
            resolvers[index] = resolverTypes[index].createResolver(parameterContext);
        }
        
        return resolvers[index].resolve(parameterContext, testInput, model);
    }
    
    private enum ResolverType {
        
        CONVERTER {
            @Override
            Resolver createResolver(ParameterContext parameterContext) {
                try {
                    return AnnotationUtils.findAnnotation(parameterContext.getParameter(), ConvertWith.class).map(ConvertWith::value).map(clazz -> (ArgumentConverter) ReflectionUtils.newInstance(clazz)).map(converter -> AnnotationConsumerInitializer.initialize(parameterContext.getParameter(), converter)).map(Converter::new).orElse(Converter.DEFAULT);
                } catch (Exception e) {
                    throw parameterResolutionException("Error creating ParameterConverter", e, parameterContext);
                }
            }
        },
        
        AGGREGATOR {
            @Override
            Resolver createResolver(ParameterContext parameterContext) {
                try {
                    return AnnotationUtils.findAnnotation(parameterContext.getParameter(), AggregateWith.class).map(AggregateWith::value).map(clazz -> (ArgumentsAggregator) ReflectionSupport.newInstance(clazz)).map(Aggregator::new).orElse(Aggregator.DEFAULT);
                } catch (Exception e) {
                    throw parameterResolutionException("Error creating ArgumentsAggregator", e, parameterContext);
                }
            }
        };
        
        abstract Resolver createResolver(ParameterContext parameterContext);
        
    }
    
    private interface Resolver {
        
        Object resolve(ParameterContext parameterContext, Combination testInput, InputParameterModel model);
        
    }
    
    private static class Converter implements Resolver {
        
        private static final Converter DEFAULT = new Converter(DefaultArgumentConverter.INSTANCE);
        
        private final ArgumentConverter parameterConverter;
        
        Converter(ArgumentConverter parameterConverter) {
            this.parameterConverter = parameterConverter;
        }
        
        @Override
        public Object resolve(ParameterContext parameterContext, Combination testInput, InputParameterModel model) {
            final Object value = testInput.getRawValue(model.getParameters().get(parameterContext.getIndex()));
            try {
                return parameterConverter.convert(value, parameterContext);
            } catch (Exception e) {
                throw parameterResolutionException("Error converting parameter", e, parameterContext);
            }
        }
        
    }
    
    private static class Aggregator implements Resolver {
        
        private static final Aggregator DEFAULT = new Aggregator((accessor, context) -> accessor);
        
        private final ArgumentsAggregator argumentsAggregator;
        
        Aggregator(ArgumentsAggregator argumentsAggregator) {
            this.argumentsAggregator = argumentsAggregator;
        }
        
        @Override
        public Object resolve(ParameterContext parameterContext, Combination testInput, InputParameterModel model) {
            
            final ArgumentsAccessor accessor = new DefaultArgumentsAccessor(IntStream.range(0, model.size()).mapToObj(index -> model.getParameters().get(index)).map(testInput::getRawValue).toArray());
            try {
                return argumentsAggregator.aggregateArguments(accessor, parameterContext);
            } catch (Exception e) {
                throw parameterResolutionException("Error aggregating arguments for parameter", e, parameterContext);
            }
        }
        
    }
    
    private static ParameterResolutionException parameterResolutionException(String message, Exception cause, ParameterContext parameterContext) {
        String fullMessage = message + " at index " + parameterContext.getIndex();
        if (StringUtils.isNotBlank(cause.getMessage())) {
            fullMessage += ": " + cause.getMessage();
        }
        
        return new ParameterResolutionException(fullMessage, cause);
    }
    
}
