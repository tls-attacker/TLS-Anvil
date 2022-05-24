/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.ResultsCollector;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.FileAppender;
import org.apache.logging.log4j.core.config.AppenderRef;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.layout.PatternLayout;

import java.io.*;
import java.nio.file.Path;

/**
 * Using LogFile a new file for logging can be created. The file can be appended using the 'log' function. Additionally
 * a log4j2 pattern for logging can be defined (see https://logging.apache.org/log4j/2.x/manual/layouts.html#PatternLayout).
 * log4j2 is used for logging.
 */
public class LogFile {
    protected Logger logger;

    private void generateLogger(String path, String pattern) {
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);

        Configuration config = ctx.getConfiguration();

        String uniqueName = path.replaceAll("[^A-Za-z]", "_");
        String loggerName = "Logger"+uniqueName;
        String appenderName = "Appender"+uniqueName;

        FileAppender fileAppender =
                FileAppender.newBuilder()
                        .setName(appenderName)
                        .setLayout(
                                PatternLayout.newBuilder()
                                        .withPattern(pattern)
                                        .build())
                        .withFileName(path)
                        .build();

        fileAppender.start();

        AppenderRef[] refs = new AppenderRef[] { AppenderRef.createAppenderRef(fileAppender.getName(), null, null) };

        LoggerConfig loggerConfig = LoggerConfig.createLogger(false, Level.ALL, loggerName, "true", refs, null, config, null);
        loggerConfig.addAppender(fileAppender, Level.ALL, null);

        ctx.getConfiguration().addLogger(loggerName, loggerConfig);

        ctx.updateLoggers();

        this.logger = ctx.getLogger(loggerName);

    }

    public LogFile(Path folderDirectoryPath, String fileName){
        this(folderDirectoryPath, fileName, "%m");
    }

    public LogFile(Path folderDirectoryPath, String fileName, String logPattern){
        Path path = folderDirectoryPath.resolve(fileName);
        File logFile = path.toFile();
        if(logFile.exists()){
            logFile.delete();
        }
        generateLogger(path.toAbsolutePath().toString(), logPattern);

    }

    public void log(String data){
        logger.info(data);
    }

}
