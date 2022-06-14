/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector;

import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * LogFile used for general information
 */
public class GeneralInfoLogFile extends LogFile{

    private final ConfigurationOptionsConfig config;

    public GeneralInfoLogFile(Path folderDirectoryPath, String fileName, ConfigurationOptionsConfig config){
        super(folderDirectoryPath, fileName);
        this.config = config;
        init();
    }

    private void init(){
        String data = "";
        data += String.format("Library Name,%s\n", config.getTlsLibraryName());
        data += String.format("Library Version,%s\n", config.getTlsVersionName());

        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
        LocalDateTime now = LocalDateTime.now();

        data += String.format("Timestamp,%s\n", dtf.format(now));

        log(data+"\n");
    }

}
