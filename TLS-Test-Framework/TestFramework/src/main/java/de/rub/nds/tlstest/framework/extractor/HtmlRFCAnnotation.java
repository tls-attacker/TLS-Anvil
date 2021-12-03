package de.rub.nds.tlstest.framework.extractor;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HtmlRFCAnnotation {

    private static final Logger LOGGER = LogManager.getLogger();
    
    public static final String COLOR_COVERED = "green";
    public static final String COLOR_DEPRECATED = "blue";
    public static final String COLOR_OUT_OF_SCOPE = "orange";
    public static final String COLOR_IMPLICIT = "pink";
    public static final String COLOR_PROTOCOL_EXTENSION = "gray";
    public static final String COLOR_BLACKBOX_UNTESTABLE = "cyan";
    public static final String COLOR_MUST = "red";

    public static final String DIRECTORY_DEPRECATED = "deprecated";
    public static final String DIRECTORY_OUT_OF_SCOPE = "out_of_scope";
    public static final String DIRECTORY_IMPLICIT = "implicit";
    public static final String DIRECTORY_PROTOCOL_EXTENSION = "protocol_extensions";
    public static final String DIRECTORY_BLACKBOX_UNTESTABLE = "untestable";

    public static LinkedHashMap<String, List<String>> getAnnotations(int rfcNumber, String path) {
        LinkedHashMap<String, List<String>> annotationMap = new LinkedHashMap<>();
        annotationMap.put(DIRECTORY_DEPRECATED, getAnnotations(path + DIRECTORY_DEPRECATED, rfcNumber));
        annotationMap.put(DIRECTORY_OUT_OF_SCOPE, getAnnotations(path + DIRECTORY_OUT_OF_SCOPE, rfcNumber));
        annotationMap.put(DIRECTORY_IMPLICIT, getAnnotations(path + DIRECTORY_IMPLICIT, rfcNumber));
        annotationMap.put(DIRECTORY_PROTOCOL_EXTENSION, getAnnotations(path + DIRECTORY_PROTOCOL_EXTENSION, rfcNumber));
        annotationMap.put(DIRECTORY_BLACKBOX_UNTESTABLE, getAnnotations(path + DIRECTORY_BLACKBOX_UNTESTABLE, rfcNumber));
        return annotationMap;
    }

    private static List<String> getAnnotations(String annotationPath, int rfcNumber) {
        List<String> annotatedPassages = new LinkedList<>();
        try(BufferedReader reader = new BufferedReader(new FileReader(annotationPath + "/" + rfcNumber + ".txt")))  {                       
            String line;
            while ((line = reader.readLine()) != null) {
                if(line.length() > 1) {
                    annotatedPassages.add(line);
                }
            }
        } catch (IOException ignored) {
        }
        return annotatedPassages;
    }
    
    public static String getColorForDirectory(String directory) {
        switch(directory) {
            case DIRECTORY_DEPRECATED:
                return COLOR_DEPRECATED;
            case DIRECTORY_BLACKBOX_UNTESTABLE:
                return COLOR_BLACKBOX_UNTESTABLE;
            case DIRECTORY_IMPLICIT:
                return COLOR_IMPLICIT;
            case DIRECTORY_OUT_OF_SCOPE:
                return COLOR_OUT_OF_SCOPE;
            case DIRECTORY_PROTOCOL_EXTENSION:
                return COLOR_PROTOCOL_EXTENSION;
            default:
                throw new IllegalArgumentException(directory + " is not a known annotation identifier");
        }
    }
}
