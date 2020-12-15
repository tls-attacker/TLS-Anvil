package de.rwth.swc.coffee4j.engine.constraint;

import org.chocosolver.solver.Model;

public class NegatedConstraint extends Constraint {

    public NegatedConstraint(Constraint constraint) {
        super(constraint);
    }
    
    @Override
    public org.chocosolver.solver.constraints.Constraint apply(final Model model) {
        return super.apply(model).getOpposite();
    }
}
