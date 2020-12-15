package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import org.chocosolver.solver.Model;

import java.util.Collection;
import java.util.List;

class HardConstraintChecker extends ModelBasedConstraintChecker {

    HardConstraintChecker(final TestModel testModel,
                          List<Constraint> exclusionConstraints,
                          List<Constraint> errorConstraints) {
        super(createModel(testModel, exclusionConstraints, errorConstraints));
    }
    
    private static Model createModel(TestModel testModel,
                                     List<Constraint> exclusionConstraints,
                                     List<Constraint> errorConstraints) {
        final Model model = new Model();
        createVariables(testModel, model);
        createConstraints(exclusionConstraints, errorConstraints, model);
        
        return model;
    }
    
    private static void createVariables(TestModel testModel, Model model) {
        for (int i = 0; i < testModel.getNumberOfParameters(); i++) {
            int parameterSize = testModel.getParameterSizes()[i];
            String key = String.valueOf(i);
            
            model.intVar(key, 0, parameterSize - 1);
        }
    }
    
    private static void createConstraints(Collection<Constraint> exclusionConstraints,
                                          Collection<Constraint> errorConstraints,
                                          Model model) {
        for (Constraint constraint : exclusionConstraints) {
            constraint.apply(model).post();
        }
        
        for (Constraint errorConstraint : errorConstraints) {
            errorConstraint.apply(model).post();
        }
    }
}
