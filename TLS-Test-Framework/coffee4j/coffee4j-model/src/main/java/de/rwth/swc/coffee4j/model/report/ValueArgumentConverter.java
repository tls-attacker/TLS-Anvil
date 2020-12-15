package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.engine.report.ValueArgument;
import de.rwth.swc.coffee4j.model.Value;

/**
 * A {@link ArgumentConverter} cor converting {@link ValueArgument}s
 * into {@link Value} instances for reporting.
 */
public class ValueArgumentConverter extends ModelBasedArgumentConverter {
    
    @Override
    public boolean canConvert(Object argument) {
        return argument instanceof ValueArgument;
    }
    
    @Override
    public Object convert(Object argument) {
        final ValueArgument valueArgument = (ValueArgument) argument;
        
        return modelConverter.convertValue(valueArgument.getParameter(), valueArgument.getValue());
    }
    
}
