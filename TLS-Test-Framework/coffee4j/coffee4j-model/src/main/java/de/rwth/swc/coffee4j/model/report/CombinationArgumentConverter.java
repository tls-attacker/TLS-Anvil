package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.engine.report.CombinationArgument;
import de.rwth.swc.coffee4j.model.Combination;

/**
 * A {@link ArgumentConverter} cor converting {@link CombinationArgument}s
 * into {@link Combination} instances for reporting.
 */
public class CombinationArgumentConverter extends ModelBasedArgumentConverter {
    
    @Override
    public boolean canConvert(Object argument) {
        return argument instanceof CombinationArgument;
    }
    
    @Override
    public Object convert(Object argument) {
        final CombinationArgument combinationArgument = (CombinationArgument) argument;
        
        return modelConverter.convertCombination(combinationArgument.getCombination());
    }
    
}
