package de.rwth.swc.coffee4j.engine.report;

/**
 * Specifies an easy means to filter report content based on severity. This is basically the same mechanism as used by
 * any other reporting or logging framework.
 */
public enum ReportLevel {
    
    /**
     * Should be used if the report is only used for real in depth debugging by developers who know the code.
     */
    TRACE(0),
    /**
     * Should be used for general debugging information. This may not only help developers but also users who want
     * to understand a problem with the application.
     */
    DEBUG(1),
    /**
     * Should be used for normal logging of things such as start/stop/configuration, but not everything. This is
     * generally a level in which users are interested in for a quick overview of what could have went wrong, or
     * what is happening in the application to know if application is running correctly.
     */
    INFO(2),
    /**
     * Should be used for things which could later likely cause failures or any very special reporting from
     * level info which states a non-normal condition.
     */
    WARN(3),
    /**
     * Should be used for things fatal to the current operation, but not the whole process.
     */
    ERROR(4),
    /**
     * An error which leads to the complete shutdown, so one from which the application cannot possible recover.
     */
    FATAL(5);
    
    private final int severity;
    
    ReportLevel(int severity) {
        this.severity = severity;
    }
    
    /**
     * Checks if the level given to the method is higher than the own level, or at least equal.
     * For example, this method would return {@code true} if called on info with info, warn, error or fatal, but
     * {@code false} if called with trace or debug as those levels are below info.
     *
     * @param otherLevel the level to which the own one is compared
     * @return whether the given level is worse or equals (depending on the severity)
     */
    public boolean isWorseThanOrEqualTo(ReportLevel otherLevel) {
        return severity >= otherLevel.severity;
    }
    
}
