/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.ResultsCollector;

import java.io.*;
import java.nio.file.Path;

public class LogFile {
    protected Path path;
    protected String fileName;

    public LogFile(Path folderDirectoryPath, String fileName){
        path = folderDirectoryPath.resolve(fileName);
        File logFile = path.toFile();
        if(logFile.exists()){
            logFile.delete();
        }
    }

    public void appendln(String data){
        append(data, "\n");
    }

    public void append(String data, String end){
        try {
            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(path.toFile(), true)));
            if(end == "\n"){
                out.println(data);
            }
            else{
                out.print(data+end);
                out.flush();
            }
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(String.format("Cannot access file '%s'.", path.toAbsolutePath()));
        }
    }

}
