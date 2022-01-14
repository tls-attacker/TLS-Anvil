package de.rub.nds.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameter;

public class TestExtractorDelegate {
    @Parameter(names = "-outputFolder", description = "Folder to output annotated RFC HTML files")
    private String outputFolder = "./";

    @Parameter(names = "-detailed", description = "Print more detailed test information")
    private boolean detailed = false;
    
    public String getOutputFolder() {
        return outputFolder;
    }

    public void setOutputFolder(String outputFolder) {
        this.outputFolder = outputFolder;
    }

    public boolean isDetailed() {
        return detailed;
    }

    public void setDetailed(boolean detailed) {
        this.detailed = detailed;
    }
}
