package de.rub.nds.tlstest.framework.extractor;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.config.TestConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;
import org.reflections.scanners.TypeAnnotationsScanner;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class TestCaseExtractor {
    private static final Logger LOGGER = LogManager.getLogger(TestCaseExtractor.class);

    private String packageName;

    public TestCaseExtractor(String packageName) {
        this.packageName = packageName;
    }


    public void start() {
        Reflections reflections = new Reflections(packageName, new MethodAnnotationsScanner());
        Set<Method> testMethodsRaw = reflections.getMethodsAnnotatedWith(TestDescription.class);
        testMethodsRaw.addAll(reflections.getMethodsAnnotatedWith(TlsTest.class));

        Set<ExtractionMethod> testMethods = testMethodsRaw.stream()
                .filter(i -> i.getAnnotation(RFC.class) != null || i.getDeclaringClass().getAnnotation(RFC.class) != null)
                .map(ExtractionMethod::new)
                .filter(i -> !i.getDescription().matches("^[\\s\\n]*$"))
                .collect(Collectors.toSet());

        LOGGER.info("Found {} RFC tests", testMethods.size());

        Map<Integer, List<ExtractionMethod>> rfcMap = new HashMap<>();
        testMethods.forEach(i -> {
            int rfcNumber = i.getRFCAnnotation().number();
            if (!rfcMap.containsKey(rfcNumber)) {
                rfcMap.put(rfcNumber, new ArrayList<>());
            }

            rfcMap.get(rfcNumber).add(i);
        });


        rfcMap.keySet().forEach(rfcNumber -> {
            List<ExtractionMethod> testCases = rfcMap.get(rfcNumber);
            RFCHtml rfcHtml = new RFCHtml(rfcNumber);
            applyHtmlRFCAnnotations(rfcHtml, rfcNumber);
            LOGGER.info("RFC {}: Found {} test cases", rfcNumber, testCases.size());
            
            for (ExtractionMethod testCase : testCases) {
                rfcHtml.markText(testCase.getDescription(), HtmlRFCAnnotation.COLOR_COVERED, false, false);
            }

            rfcHtml.saveToFolder(TestContext.getInstance().getConfig().getTestExtractorDelegate().getOutputFolder());
        });

    }
    
    private void applyHtmlRFCAnnotations(RFCHtml rfcHtml, int rfcNumber) {
        rfcHtml.markText("MUST", HtmlRFCAnnotation.COLOR_MUST, true, true);
        Map<String, List<String>> annotationMap = HtmlRFCAnnotation.getAnnotations(rfcNumber, "annotations/");
        for(String annotationDirectory : annotationMap.keySet()) {
            for(String annotatedPassage: annotationMap.get(annotationDirectory)) {
                rfcHtml.markText(annotatedPassage, HtmlRFCAnnotation.getColorForDirectory(annotationDirectory), true, false);
            }
        }
    }


    private static class ExtractionMethod {
        private final Method m;
        private final RFC rfcAnnotation;
        private String description;

        public ExtractionMethod(Method method) {
            this.m = method;
            this.rfcAnnotation = getRFCAnnotation();
            TestDescription description = method.getAnnotation(TestDescription.class);
            if (description != null) {
                this.description = description.value();
            }

            TlsTest desc = method.getAnnotation(TlsTest.class);
            if (desc != null) {
                this.description = desc.description();
            }

            if (description == null && desc == null) {
                LOGGER.warn("No description found {}", method);
            }
        }

        public RFC getRFCAnnotation() {
            if (rfcAnnotation != null) return rfcAnnotation;

            String pName = m.getDeclaringClass().getPackage().getName();
            Pattern rfcPattern = Pattern.compile("rfc([0-9]+)");
            Matcher matcher = rfcPattern.matcher(pName);
            int rfcNumber = -1;
            if (matcher.find()) {
                rfcNumber = Integer.parseInt(matcher.group(1));
            }

            RFC annotation = m.getAnnotation(RFC.class);
            if (annotation == null) {
                annotation = m.getDeclaringClass().getAnnotation(RFC.class);
            }

            if (annotation.number() != rfcNumber) {
                LOGGER.warn("RFC number mismatch: Detected {} vs Expected {} for {}.{}", annotation.number(), rfcNumber, this.m.getDeclaringClass().getName(), this.m.getName());
            }

            return annotation;
        }

        public String getDescription() {
            if (description.matches("^[\\s\\n]*$")) {
                LOGGER.warn("Empty description {}", m);
            }
            return description;
        }
    }
}
