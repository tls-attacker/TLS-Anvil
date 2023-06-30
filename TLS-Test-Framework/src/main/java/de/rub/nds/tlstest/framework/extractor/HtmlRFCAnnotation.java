/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.extractor;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public enum HtmlRFCAnnotation {
    MUST("red", null),
    MUST_NOT("red", null),
    COVERED("green", null),
    IMPLICIT("blue", "implicit"),
    OUT_OF_SCOPE("blue", "out_of_scope"),
    PROTOCOL_EXTENSION("blue", "protocol_extensions"),
    BLACKBOX_UNTESTABLE("blue", "untestable"),
    DEPRECATED("blue", "deprecated"),
    CONTRADICTORY("blue", "contradictory");

    private static final Logger LOGGER = LogManager.getLogger();

    private final String color;
    private final String directory;

    private HtmlRFCAnnotation(String color, String directory) {
        this.color = color;
        this.directory = directory;
    }

    public static LinkedHashMap<HtmlRFCAnnotation, List<String>> getAnnotations(
            int rfcNumber, String path) {
        LinkedHashMap<HtmlRFCAnnotation, List<String>> annotationMap = new LinkedHashMap<>();
        for (HtmlRFCAnnotation annotationType : HtmlRFCAnnotation.values()) {
            if (annotationType.isPredefinedAnnotation()) {
                annotationMap.put(
                        annotationType,
                        getAnnotations(path + annotationType.getDirectory(), rfcNumber));
            }
        }
        return annotationMap;
    }

    private static List<String> getAnnotations(String annotationPath, int rfcNumber) {
        List<String> annotatedPassages = new LinkedList<>();
        try (BufferedReader reader =
                new BufferedReader(new FileReader(annotationPath + "/" + rfcNumber + ".txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.length() > 1) {
                    annotatedPassages.add(line);
                }
            }
        } catch (IOException ignored) {
        }
        return annotatedPassages;
    }

    public String getColor() {
        return color;
    }

    public String getDirectory() {
        return directory;
    }

    public boolean isPredefinedAnnotation() {
        return !(this == MUST || this == MUST_NOT || this == COVERED);
    }
}
