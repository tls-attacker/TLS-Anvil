package de.rwth.swc.coffee4j.junit.provider.configuration.converter;

import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.junit.provider.Loader;
import de.rwth.swc.coffee4j.model.report.CombinationArgumentConverter;
import de.rwth.swc.coffee4j.model.report.ParameterArgumentConverter;
import de.rwth.swc.coffee4j.model.report.TupleListArgumentConverter;
import de.rwth.swc.coffee4j.model.report.ValueArgumentConverter;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumerInitializer;
import org.junit.platform.commons.util.ReflectionUtils;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.platform.commons.util.AnnotationUtils.findRepeatableAnnotations;

/**
 * Class for loading multiple {@link ArgumentConverter} via {@link ConverterProvider}. These providers are
 * discovered using the {@link ConverterSource} repeatable annotations. As such, multiple {@link ArgumentConverter}
 * provided by each {@link ConverterSource} are aggregated into one single list in this loader.
 * <p>
 * Per default, {@link CombinationArgumentConverter}, {@link ParameterArgumentConverter},
 * {@link TupleListArgumentConverter}, and {@link ValueArgumentConverter} are added to the end of the list.
 * Due to the way these argument converters are used inside the framework, it is possible to "overwrite"
 * argument conversion for any type which would be converted by the default converters by just specifying one.
 * The default argument converters will always be last.
 */
public class ConverterLoader implements Loader<List<ArgumentConverter>> {
    
    private static final List<ArgumentConverter> DEFAULT_ARGUMENT_RESOLVERS = Arrays.asList(new CombinationArgumentConverter(), new ParameterArgumentConverter(), new TupleListArgumentConverter(), new ValueArgumentConverter());
    
    @Override
    public List<ArgumentConverter> load(ExtensionContext extensionContext) {
        final Method testMethod = extensionContext.getRequiredTestMethod();
        
        return Stream.concat(findRepeatableAnnotations(testMethod, ConverterSource.class).stream().map(ConverterSource::value).map(ReflectionUtils::newInstance).map(provider -> AnnotationConsumerInitializer.initialize(testMethod, provider)).map(provider -> provider.provide(extensionContext)).filter(Objects::nonNull).flatMap(Collection::stream).filter(Objects::nonNull), DEFAULT_ARGUMENT_RESOLVERS.stream()).collect(Collectors.toList());
    }
    
}
