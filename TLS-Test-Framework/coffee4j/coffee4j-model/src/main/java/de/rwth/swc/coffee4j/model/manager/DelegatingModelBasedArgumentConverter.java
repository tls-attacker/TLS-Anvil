package de.rwth.swc.coffee4j.model.manager;

import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.converter.ModelConverter;
import de.rwth.swc.coffee4j.model.report.ModelBasedArgumentConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

class DelegatingModelBasedArgumentConverter extends ModelBasedArgumentConverter {
    
    private final List<ArgumentConverter> argumentConverters;
    
    DelegatingModelBasedArgumentConverter(Collection<ArgumentConverter> argumentConverters) {
        Preconditions.notNull(argumentConverters);
        Preconditions.check(!argumentConverters.contains(null));
        
        this.argumentConverters = new ArrayList<>(argumentConverters);
    }
    
    @Override
    public void initialize(ModelConverter modelConverter) {
        for (ArgumentConverter argumentConverter : argumentConverters) {
            if (argumentConverter instanceof ModelBasedArgumentConverter) {
                ((ModelBasedArgumentConverter) argumentConverter).initialize(modelConverter);
            }
        }
    }
    
    @Override
    public boolean canConvert(Object argument) {
        for (ArgumentConverter argumentConverter : argumentConverters) {
            if (argumentConverter.canConvert(argument)) {
                return true;
            }
        }
        
        return false;
    }
    
    @Override
    public Object convert(Object argument) {
        for (ArgumentConverter argumentConverter : argumentConverters) {
            if (argumentConverter.canConvert(argument)) {
                return argumentConverter.convert(argument);
            }
        }
        
        throw new IllegalStateException("This method should not be called if canConcert returns false");
    }
    
}
