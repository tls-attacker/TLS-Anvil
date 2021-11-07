package de.rwth.swc.coffee4j.engine.report;

import org.junit.jupiter.api.Test;

import java.util.function.Supplier;

class GenerationReporterTest {

    @Test
    void canCallDefaultMethodsWithNull() {
        final GenerationReporter reporter = new GenerationReporter() {
            @Override
            public void report(ReportLevel level, Report report) {

            }

            @Override
            public void report(ReportLevel level, Supplier<Report> reportSupplier) {

            }
        };

        reporter.testInputGroupGenerated(null, null);
        reporter.faultCharacterizationStarted(null, null);
        reporter.faultCharacterizationTestInputsGenerated(null, null);
        reporter.faultCharacterizationFinished(null, null);
        reporter.testInputGroupFinished(null);
    }

}
