package de.rwth.swc.coffee4j.engine.report;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.BiFunction;

/**
 * A report any algorithm inside the combinatorial test input generation can use to notify the user of events not
 * covered by life cycle reporting.
 */
public class Report {
    
    private final String resolvableReport;
    
    private final Object[] arguments;
    
    private final BiFunction<String, Object[], String> reportResolver;
    
    private String resolvedReport;
    
    /**
     * Copy constructor.
     *
     * @param report the report to be copied
     */
    public Report(Report report) {
        resolvableReport = report.resolvableReport;
        arguments = Arrays.copyOf(report.arguments, report.arguments.length);
        reportResolver = report.reportResolver;
        resolvedReport = report.resolvedReport;
    }
    
    /**
     * Creates a new report based on a resolvable string. The given function should be able to resolve the string
     * to something sensible using the supplied arguments. The string cannot be resolved at the beginning, since
     * {@link ArgumentConverter}s may be used to convert the given argument, changing the meaning of the report.
     *
     * @param resolvableReport a report which can be resolved with the resolver and arguments. Must not be {@code null}
     * @param reportResolver   to resolve the report ot a sensible string. Must not be {@code null}
     * @param arguments        all arguments used to enrich the report. May be empty, but not {@code null}
     */
    public Report(String resolvableReport, BiFunction<String, Object[], String> reportResolver, Object... arguments) {
        this.resolvableReport = Preconditions.notNull(resolvableReport);
        this.reportResolver = Preconditions.notNull(reportResolver);
        this.arguments = Preconditions.notNull(arguments);
    }
    
    public static Report report(String report, Object... arguments) {
        return new Report(report, MessageFormat::format, arguments);
    }
    
    /**
     * @return the report as supplied to the constructor (not resolved with any arguments)
     */
    public String getResolvableReport() {
        return resolvableReport;
    }
    
    /**
     * Once this method has been called, the report will not be resolved again, so any changing arguments after a call
     * to this method are not respected.
     *
     * @return the report resolved using the given resolver and the arguments.
     */
    public String getResolvedReport() {
        if (resolvedReport == null) {
            resolvedReport = reportResolver.apply(resolvableReport, arguments);
        }
        
        return resolvedReport;
    }
    
    /**
     * Converts all arguments given to the constructor using the given {@link ArgumentConverter}.
     *
     * @param argumentConverter an converter to change any argument into an other representation
     */
    public void convertArguments(ArgumentConverter argumentConverter) {
        for (int i = 0; i < arguments.length; i++) {
            final Object argument = arguments[i];
            if (argumentConverter.canConvert(argument)) {
                arguments[i] = argumentConverter.convert(argument);
            }
        }
    }
    
    public Object[] getArguments() {
        return Arrays.copyOf(arguments, arguments.length);
    }
    
    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        
        final Report other = (Report) object;
        return Objects.equals(resolvableReport, other.resolvableReport) && Arrays.equals(arguments, other.arguments);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(resolvableReport, arguments);
    }
    
    @Override
    public String toString() {
        return "Report{" + "resolvableReport='" + resolvableReport + '\'' + ", replacingElements=" + Arrays.toString(arguments) + '}';
    }
    
}
