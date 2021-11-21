package de.rub.nds.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameter;

public class TestExtractorDelegate {
    @Parameter(names = "-outputFolder", description = "Folder to output annotated RFC HTML files")
    private String outputFolder = "./";

    public String getOutputFolder() {
        return outputFolder;
    }

    public void setOutputFolder(String outputFolder) {
        this.outputFolder = outputFolder;
    }
}
