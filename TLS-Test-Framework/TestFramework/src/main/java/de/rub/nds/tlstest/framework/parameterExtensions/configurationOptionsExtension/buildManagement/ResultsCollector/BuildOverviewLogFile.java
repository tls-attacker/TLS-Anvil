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

import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;

import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * LogFile to give an overview of all used builds including build time and configuration options.
 */
public class BuildOverviewLogFile extends LogFile {
    private ConfigurationOptionsConfig config;
    private List<ConfigOptionDerivationType> optionHeaders;

    private Set<String> loggedDockerTags;

    private Integer number;

    public BuildOverviewLogFile(Path folderDirectoryPath, String fileName, ConfigurationOptionsConfig config){
        super(folderDirectoryPath, fileName);
        this.config = config;
        loggedDockerTags = new HashSet<>();
        init();
    }

    private void init(){
        List<String> header = new LinkedList<>();
        optionHeaders = new ArrayList<>(config.getEnabledConfigOptionDerivations());
        Collections.sort(optionHeaders, Comparator.comparing(Enum::name));

        //String header = "Docker Tag,Build Time,";
        header.add("No");
        header.add("Docker Tag");
        header.add("Build Time (in sec)");
        for(ConfigOptionDerivationType optionHeaderEntry : optionHeaders){
            header.add(optionHeaderEntry.name());
        }
        log(String.join(",", header)+"\n");
        number = 1;
    }

    private String getTimeStringFromMs(long timeInMs){
        long sec = TimeUnit.MILLISECONDS.toSeconds(timeInMs);
        long ms = timeInMs - TimeUnit.SECONDS.toMillis(sec);

        return String.format("%d.%d", sec, ms);
    }

    public void logBuild(Set<ConfigurationOptionDerivationParameter> optionSet, String dockerTag, long buildTime){
        if(loggedDockerTags.contains(dockerTag)){
            return;
        }
        else{
            loggedDockerTags.add(dockerTag);
        }

        List<String> line = new LinkedList<>();
        line.add(number.toString());
        number += 1;
        line.add(dockerTag);
        if(buildTime >= 0){
            line.add(getTimeStringFromMs(buildTime));
        }
        else{
            line.add("EXISTED");
        }

        Map<ConfigOptionDerivationType, ConfigurationOptionValue> optionTypeToValue = new HashMap<>();
        for(ConfigurationOptionDerivationParameter configOptionDervivation : optionSet){
            ConfigOptionDerivationType type = (ConfigOptionDerivationType) configOptionDervivation.getType();
            optionTypeToValue.put(type, configOptionDervivation.getSelectedValue());
        }

        for(ConfigOptionDerivationType headerField : optionHeaders){
            if(optionTypeToValue.containsKey(headerField)){
                line.add(optionTypeToValue.get(headerField).toString());
            }
            else{
                line.add("N/A");
            }
        }

        log(String.join(",", line)+"\n");
    }

}
