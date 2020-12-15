package de.rwth.swc.coffee4j.engine.report;

import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;

import java.util.function.Supplier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;

class ReporterTest {
    
    private static final Report TRACE_TEXT = Report.report("trace");
    private static final Report TRACE_SUPPLIER_TEXT = Report.report("traceSupplier");
    private static final Report DEBUG_TEXT = Report.report("debug");
    private static final Report DEBUG_SUPPLIER_TEXT = Report.report("debugSupplier");
    private static final Report INFO_TEXT = Report.report("info");
    private static final Report INFO_SUPPLIER_TEXT = Report.report("infoSupplier");
    private static final Report WARN_TEXT = Report.report("warn");
    private static final Report WARN_SUPPLIER_TEXT = Report.report("warnSupplier");
    private static final Report ERROR_TEXT = Report.report("error");
    private static final Report ERROR_SUPPLIER_TEXT = Report.report("errorSupplier");
    private static final Report FATAL_TEXT = Report.report("fatal");
    private static final Report FATAL_SUPPLIER_TEXT = Report.report("fatalSupplier");
    
    @Test
    @SuppressWarnings("unchecked")
    void defaultReportImplementations() {
        final Reporter reporter = Mockito.mock(Reporter.class);
        final Supplier<Report> traceReportSupplier = () -> TRACE_SUPPLIER_TEXT;
        final Supplier<Report> debugReportSupplier = () -> DEBUG_SUPPLIER_TEXT;
        final Supplier<Report> infoReportSupplier = () -> INFO_SUPPLIER_TEXT;
        final Supplier<Report> warnReportSupplier = () -> WARN_SUPPLIER_TEXT;
        final Supplier<Report> errorReportSupplier = () -> ERROR_SUPPLIER_TEXT;
        final Supplier<Report> fatalReportSupplier = () -> FATAL_SUPPLIER_TEXT;
        
        doCallRealMethod().when(reporter).reportTrace(any(Report.class));
        doCallRealMethod().when(reporter).reportTrace(any(Supplier.class));
        doCallRealMethod().when(reporter).reportDebug(any(Report.class));
        doCallRealMethod().when(reporter).reportDebug(any(Supplier.class));
        doCallRealMethod().when(reporter).reportInfo(any(Report.class));
        doCallRealMethod().when(reporter).reportInfo(any(Supplier.class));
        doCallRealMethod().when(reporter).reportWarn(any(Report.class));
        doCallRealMethod().when(reporter).reportWarn(any(Supplier.class));
        doCallRealMethod().when(reporter).reportError(any(Report.class));
        doCallRealMethod().when(reporter).reportError(any(Supplier.class));
        doCallRealMethod().when(reporter).reportFatal(any(Report.class));
        doCallRealMethod().when(reporter).reportFatal(any(Supplier.class));
        
        reporter.reportTrace(TRACE_TEXT);
        reporter.reportTrace(traceReportSupplier);
        reporter.reportDebug(DEBUG_TEXT);
        reporter.reportDebug(debugReportSupplier);
        reporter.reportInfo(INFO_TEXT);
        reporter.reportInfo(infoReportSupplier);
        reporter.reportWarn(WARN_TEXT);
        reporter.reportWarn(warnReportSupplier);
        reporter.reportError(ERROR_TEXT);
        reporter.reportError(errorReportSupplier);
        reporter.reportFatal(FATAL_TEXT);
        reporter.reportFatal(fatalReportSupplier);
        
        InOrder inOrder = inOrder(reporter);
        inOrder.verify(reporter, times(1)).report(ReportLevel.TRACE, TRACE_TEXT);
        inOrder.verify(reporter, times(1)).report(ReportLevel.TRACE, traceReportSupplier);
        inOrder.verify(reporter, times(1)).report(ReportLevel.DEBUG, DEBUG_TEXT);
        inOrder.verify(reporter, times(1)).report(ReportLevel.DEBUG, debugReportSupplier);
        inOrder.verify(reporter, times(1)).report(ReportLevel.INFO, INFO_TEXT);
        inOrder.verify(reporter, times(1)).report(ReportLevel.INFO, infoReportSupplier);
        inOrder.verify(reporter, times(1)).report(ReportLevel.WARN, WARN_TEXT);
        inOrder.verify(reporter, times(1)).report(ReportLevel.WARN, warnReportSupplier);
        inOrder.verify(reporter, times(1)).report(ReportLevel.ERROR, ERROR_TEXT);
        inOrder.verify(reporter, times(1)).report(ReportLevel.ERROR, errorReportSupplier);
        inOrder.verify(reporter, times(1)).report(ReportLevel.FATAL, FATAL_TEXT);
        inOrder.verify(reporter, times(1)).report(ReportLevel.FATAL, fatalReportSupplier);
    }
    
}
