package de.rwth.swc.coffee4j.engine.report;

import java.util.function.Supplier;

/**
 * An interface defining a reporter which can be called by internal algorithms to notify the user of events not covered
 * by an life cycle method in the {@link GenerationReporter}. many default methods are just used to give the user
 * a better callable interface and should not be implemented by an extending class.
 */
public interface Reporter {
    
    /**
     * Calls {@link #report(ReportLevel, Report)} with the level {@link ReportLevel#TRACE} and the given report.
     *
     * @param report what should be reported at level {@link ReportLevel#TRACE}
     */
    default void reportTrace(Report report) {
        report(ReportLevel.TRACE, report);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Supplier)} with the level {@link ReportLevel#TRACE} and the given supplier.
     *
     * @param reportSupplier what should be reported if the reporter listens at level {@link ReportLevel#TRACE}
     */
    default void reportTrace(Supplier<Report> reportSupplier) {
        report(ReportLevel.TRACE, reportSupplier);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Report)} with the level {@link ReportLevel#DEBUG} and the given report.
     *
     * @param report what should be reported at level {@link ReportLevel#DEBUG}
     */
    default void reportDebug(Report report) {
        report(ReportLevel.DEBUG, report);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Supplier)} with the level {@link ReportLevel#DEBUG} and the given supplier.
     *
     * @param reportSupplier what should be reported if the reporter listens at level {@link ReportLevel#DEBUG}
     */
    default void reportDebug(Supplier<Report> reportSupplier) {
        report(ReportLevel.DEBUG, reportSupplier);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Report)} with the level {@link ReportLevel#INFO} and the given report.
     *
     * @param report what should be reported at level {@link ReportLevel#INFO}
     */
    default void reportInfo(Report report) {
        report(ReportLevel.INFO, report);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Supplier)} with the level {@link ReportLevel#INFO} and the given supplier.
     *
     * @param reportSupplier what should be reported if the reporter listens at level {@link ReportLevel#INFO}
     */
    default void reportInfo(Supplier<Report> reportSupplier) {
        report(ReportLevel.INFO, reportSupplier);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Report)} with the level {@link ReportLevel#WARN} and the given report.
     *
     * @param report what should be reported at level {@link ReportLevel#WARN}
     */
    default void reportWarn(Report report) {
        report(ReportLevel.WARN, report);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Supplier)} with the level {@link ReportLevel#WARN} and the given supplier.
     *
     * @param reportSupplier what should be reported if the reporter listens at level {@link ReportLevel#WARN}
     */
    default void reportWarn(Supplier<Report> reportSupplier) {
        report(ReportLevel.WARN, reportSupplier);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Report)} with the level {@link ReportLevel#ERROR} and the given report.
     *
     * @param report what should be reported at level {@link ReportLevel#ERROR}
     */
    default void reportError(Report report) {
        report(ReportLevel.ERROR, report);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Supplier)} with the level {@link ReportLevel#ERROR} and the given supplier.
     *
     * @param reportSupplier what should be reported if the reporter listens at level {@link ReportLevel#ERROR}
     */
    default void reportError(Supplier<Report> reportSupplier) {
        report(ReportLevel.ERROR, reportSupplier);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Report)} with the level {@link ReportLevel#FATAL} and the given report.
     *
     * @param report what should be reported at level {@link ReportLevel#FATAL}
     */
    default void reportFatal(Report report) {
        report(ReportLevel.FATAL, report);
    }
    
    /**
     * Calls {@link #report(ReportLevel, Supplier)} with the level {@link ReportLevel#FATAL} and the given supplier.
     *
     * @param reportSupplier what should be reported if the reporter listens at level {@link ReportLevel#FATAL}
     */
    default void reportFatal(Supplier<Report> reportSupplier) {
        report(ReportLevel.FATAL, reportSupplier);
    }
    
    /**
     * Reports the given {@link Report} at the specified level. The levels are used so that any {@link Reporter} may
     * filter information it wishes to receive.
     *
     * @param level  the of the report. Must not be {@code null}
     * @param report the report itself. Must not be {@code null}
     */
    void report(ReportLevel level, Report report);
    
    /**
     * This method has the same intentions as {@link #report(ReportLevel, Report)}, but a supplier is given.
     * If any big calculations need to be performed for a {@link Report} generation this method can be used to guarantee
     * lazy evaluation only if a {@link Reporter} is really interested in the report of the given level.
     *
     * @param level          the of the report. Must not be {@code null}
     * @param reportSupplier a supplier which can compute the real report. It and the returned {@link Report} must not
     *                       be {@code null}
     */
    void report(ReportLevel level, Supplier<Report> reportSupplier);
    
}
