package de.rwth.swc.coffee4j.engine.report;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ReportLevelTest {
    
    @ParameterizedTest
    @MethodSource
    void isWorseThanOrEqualTo(ReportLevel first, ReportLevel second, boolean expectedResult) {
        assertEquals(expectedResult, first.isWorseThanOrEqualTo(second));
    }
    
    private static Stream<Arguments> isWorseThanOrEqualTo() {
        return Stream.of(arguments(ReportLevel.TRACE, ReportLevel.TRACE, true), arguments(ReportLevel.TRACE, ReportLevel.DEBUG, false), arguments(ReportLevel.TRACE, ReportLevel.INFO, false), arguments(ReportLevel.TRACE, ReportLevel.WARN, false), arguments(ReportLevel.TRACE, ReportLevel.ERROR, false), arguments(ReportLevel.TRACE, ReportLevel.FATAL, false), arguments(ReportLevel.DEBUG, ReportLevel.TRACE, true), arguments(ReportLevel.DEBUG, ReportLevel.DEBUG, true), arguments(ReportLevel.DEBUG, ReportLevel.INFO, false), arguments(ReportLevel.DEBUG, ReportLevel.WARN, false), arguments(ReportLevel.DEBUG, ReportLevel.ERROR, false), arguments(ReportLevel.DEBUG, ReportLevel.FATAL, false), arguments(ReportLevel.INFO, ReportLevel.TRACE, true), arguments(ReportLevel.INFO, ReportLevel.DEBUG, true), arguments(ReportLevel.INFO, ReportLevel.INFO, true), arguments(ReportLevel.INFO, ReportLevel.WARN, false), arguments(ReportLevel.INFO, ReportLevel.ERROR, false), arguments(ReportLevel.INFO, ReportLevel.FATAL, false), arguments(ReportLevel.WARN, ReportLevel.TRACE, true), arguments(ReportLevel.WARN, ReportLevel.DEBUG, true), arguments(ReportLevel.WARN, ReportLevel.INFO, true), arguments(ReportLevel.WARN, ReportLevel.WARN, true), arguments(ReportLevel.WARN, ReportLevel.ERROR, false), arguments(ReportLevel.WARN, ReportLevel.FATAL, false), arguments(ReportLevel.ERROR, ReportLevel.TRACE, true), arguments(ReportLevel.ERROR, ReportLevel.DEBUG, true), arguments(ReportLevel.ERROR, ReportLevel.INFO, true), arguments(ReportLevel.ERROR, ReportLevel.WARN, true), arguments(ReportLevel.ERROR, ReportLevel.ERROR, true), arguments(ReportLevel.ERROR, ReportLevel.FATAL, false), arguments(ReportLevel.FATAL, ReportLevel.TRACE, true), arguments(ReportLevel.FATAL, ReportLevel.DEBUG, true), arguments(ReportLevel.FATAL, ReportLevel.INFO, true), arguments(ReportLevel.FATAL, ReportLevel.WARN, true), arguments(ReportLevel.FATAL, ReportLevel.ERROR, true), arguments(ReportLevel.FATAL, ReportLevel.FATAL, true));
    }
    
}
