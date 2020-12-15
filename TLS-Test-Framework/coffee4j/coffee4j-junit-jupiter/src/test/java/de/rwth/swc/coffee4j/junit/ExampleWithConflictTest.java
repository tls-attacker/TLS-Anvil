package de.rwth.swc.coffee4j.junit;

import de.rwth.swc.coffee4j.engine.constraint.DiagnosticConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.constraint.SoftConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.ipog.Ipog;
import de.rwth.swc.coffee4j.engine.generator.ipogneg.IpogNeg;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.configuration.generator.Generator;
import de.rwth.swc.coffee4j.junit.provider.model.ModelFromMethod;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import jdk.jshell.Diag;

import static de.rwth.swc.coffee4j.model.InputParameterModel.inputParameterModel;
import static de.rwth.swc.coffee4j.model.Parameter.parameter;
import static de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder.constrain;

/**
 * Here, a soft constraint checker is used to overcome issues related to over-constrained test models when using
 * {@link de.rwth.swc.coffee4j.engine.generator.ipogneg.IpogNeg IpogNeg}.  *
 * Possible options are
 * {@link de.rwth.swc.coffee4j.engine.constraint.SoftConstraintCheckerFactory SoftConstraintCheckerFactory}
 * and
 * {@link de.rwth.swc.coffee4j.engine.constraint.DiagnosticConstraintCheckerFactory DiagnosticConstraintCheckerFactory}.
 *
 * Please note, that {@link de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory HardConstraintCheckerFactory}
 * should be used with {@link de.rwth.swc.coffee4j.engine.generator.ipog.Ipog Ipog}.
 */
class ExampleWithConflictTest {

    @CombinatorialTest
    @ModelFromMethod("model")
    @Generator(
            algorithms = {Ipog.class, IpogNeg.class},
            factories = {HardConstraintCheckerFactory.class, DiagnosticConstraintCheckerFactory.class})
    void testExample(String title, String firstName, String givenName) {
        /* Stimulate the System under Test */
    }

    static InputParameterModel model() {
        return inputParameterModel("example")
                .parameters(
                        parameter("Title").values("Mr", "Mrs", "123"),
                        parameter("GivenName").values("John", "Jane", "123"),
                        parameter("FamilyName").values("Doe", "Foo", "123")
                ).errorConstraints(
                        constrain("Title")
                                .by((String title) -> !title.equals("123")),
                        constrain("GivenName")
                                .by((String givenName) -> !givenName.equals("123")),
                        constrain("FamilyName")
                                .by((String familyName) -> !familyName.equals("123")),
                        constrain("Title", "GivenName")
                                .by((String title, String givenName) ->
                                        !(title.equals("Mrs") && givenName.equals("John"))
                                     && !(title.equals("Mrs") && givenName.equals("123"))
                                ),
                        constrain("Title", "GivenName")
                                .by((String title, String givenName) ->
                                           !(title.equals("Mr") && givenName.equals("Jane"))
                                        && !(title.equals("Mr") && givenName.equals("123"))
                                )
                )
               .build();
    }
}
