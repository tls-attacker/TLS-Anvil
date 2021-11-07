package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.model.constraints.Constraint;

/**
 * A {@link ArgumentConverter} cor converting {@link TupleList}s
 * into {@link Constraint} instances for reporting.
 */
public class TupleListArgumentConverter extends ModelBasedArgumentConverter {
    
    @Override
    public boolean canConvert(Object argument) {
        return argument instanceof TupleList;
    }
    
    @Override
    public Object convert(Object argument) {
        final TupleList tuplesList = (TupleList) argument;
        
        return modelConverter.convertConstraint(tuplesList);
    }
    
}
