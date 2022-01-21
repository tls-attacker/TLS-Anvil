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

import java.nio.file.Path;
import java.util.*;

/**
 * LogFile to count how often  single library builds (identified by docker tags) are used by all ran tests.
 */
public class BuildAccessLogFile extends LogFile{
    Map<String, Integer> dockerTagToAccessCounter;


    public BuildAccessLogFile(Path folderDirectoryPath, String fileName){
        super(folderDirectoryPath, fileName);
        dockerTagToAccessCounter = new HashMap<>();
    }

    public void increaseAccessCounter(String dockerTag){
        if(dockerTagToAccessCounter.containsKey(dockerTag)){
            dockerTagToAccessCounter.replace(dockerTag, dockerTagToAccessCounter.get(dockerTag) + 1);
        }
        else{
            dockerTagToAccessCounter.put(dockerTag, 1);
        }
    }

    public void finalizeResults(){
        String resultsString;
        List<Map.Entry<String, Integer>> entryList =  new ArrayList<>(dockerTagToAccessCounter.entrySet());

        // Sort after occurences
        Collections.sort(entryList, Comparator.comparing(Map.Entry::getValue));

        resultsString = String.format("%s,%s\n", "Docker Tag", "Access Count");
        int totalSum = 0;
        for (Map.Entry<String, Integer> entry : entryList) {
            resultsString += String.format("%s,%d\n", entry.getKey(), entry.getValue());
            totalSum += entry.getValue();
        }
        resultsString += String.format("%s,%d\n", "Total", totalSum);

        log(resultsString);
    }

}
