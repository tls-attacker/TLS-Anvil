/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.extractor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.TextNode;

public class RFCHtml {
    private static final Logger LOGGER = LogManager.getLogger();
    private final int rfcNumber;
    private final String urlString;
    private Document origDoc;
    private Document cleanupDoc;
    private List<OffsetTextNode> nodeOffsetIndex = null;
    private final Map<HtmlRFCAnnotation, Integer> annotationMustCounter = new HashMap<>();
    private final Map<HtmlRFCAnnotation, Integer> annotationMustNotCounter = new HashMap<>();
    private final List<MarkedPassage> mustNotPositions = new LinkedList<>();
    private final List<MarkedPassage> mustPositions = new LinkedList<>();
    private final List<MarkedPassage> remainingMustAndNot = new LinkedList<>();
    ;

    public RFCHtml(int rfcNumber) {
        this.rfcNumber = rfcNumber;
        this.urlString = String.format("https://datatracker.ietf.org/doc/html/rfc%d", rfcNumber);
        this.load();
    }

    protected RFCHtml(String htmlString) {
        this.rfcNumber = 0;
        this.urlString = "http://localhost";
        this.origDoc = Jsoup.parse(htmlString, urlString);
        this.cleanupDoc = origDoc.clone();
    }

    private void load() {
        try {
            origDoc = Jsoup.connect(urlString).get();
            this.cleanup();
        } catch (Exception e) {
            LOGGER.error("Error getting RFC document", e);
        }
    }

    private void cleanup() {
        cleanupDoc = Document.createShell(urlString);
        Element preElem = cleanupDoc.body().appendElement("pre");
        preElem.id("main");

        Document origDocCopy = origDoc.clone();
        origDocCopy.getElementsByClass("noprint").remove();
        origDocCopy
                .getElementsByClass("newpage")
                .forEach(
                        i -> {
                            // remove page header and footer
                            //            i.child(0).remove();
                            i.child(1).remove();
                            if (i.childrenSize() > 0) {
                                i.child(i.childrenSize() - 1).remove();
                            }

                            // remove leading whitespace text nodes of a page
                            List<TextNode> nodes = getChildNodesRecurisvly(i);
                            List<TextNode> toRemove = new ArrayList<>();
                            for (TextNode node : nodes) {
                                if (node.toString().matches("^[\\s\\n]+$")) {
                                    node.remove();
                                    toRemove.add(node);
                                    break;
                                }
                            }
                            nodes.removeAll(toRemove);

                            // remove leading/trailing new lines of a page
                            if (nodes.size() > 0) {
                                TextNode first = nodes.get(0);
                                first.text(first.getWholeText().replaceAll("^[\\n]+", ""));

                                TextNode last = nodes.get(nodes.size() - 1);
                                last.text(last.getWholeText().replaceAll("[\\n]+$", "\n\n"));
                            }

                            preElem.appendChildren(i.childNodes());
                        });

        if (origDocCopy.getElementsByClass("newpage").size() == 0) {
            preElem.appendChildren(
                    origDocCopy
                            .getElementsByClass("draftcontent")
                            .get(0)
                            .getElementsByTag("pre")
                            .get(0)
                            .childNodes());
        }
    }

    private List<TextNode> getChildNodesRecurisvly(Node node) {
        List<TextNode> childNodes = new ArrayList<>();
        for (Node j : node.childNodes()) {
            if (j.childNodeSize() > 0) {
                childNodes.addAll(getChildNodesRecurisvly(j));
            } else if (j instanceof TextNode) {
                childNodes.add((TextNode) j);
            }
        }

        return childNodes;
    }

    private void createTextNodeOffsetIndex() {
        if (nodeOffsetIndex == null) {
            nodeOffsetIndex = new ArrayList<>();
        }
        Element preElem = this.cleanupDoc.getElementsByTag("pre").first();
        int offset = 0;
        for (TextNode i : getChildNodesRecurisvly(preElem)) {
            OffsetTextNode offsetNode = new OffsetTextNode(i, offset);
            nodeOffsetIndex.add(offsetNode);
            offset += i.getWholeText().length();
        }

        Collections.sort(nodeOffsetIndex);
    }

    public void findMustAndNotPositions() {
        if (nodeOffsetIndex == null) {
            createTextNodeOffsetIndex();
        }
        String pattern = "MUST NOT";

        String text = this.cleanupDoc.getElementsByTag("pre").first().wholeText();
        Matcher matcher = Pattern.compile(pattern).matcher(text);
        while (matcher.find()) {
            int startIndex = matcher.start();
            int endIndex = matcher.end();
            mustNotPositions.add(new MarkedPassage(startIndex, endIndex));
            for (TextNode node : getTextNodesBetween(startIndex, endIndex)) {
                node.wrap(
                        String.format(
                                "<span style=\"color: %s;\"></span>",
                                HtmlRFCAnnotation.MUST_NOT.getColor()));
            }
        }

        pattern = "MUST";
        matcher = Pattern.compile(pattern).matcher(text);
        while (matcher.find()) {
            int startIndex = matcher.start();
            int endIndex = matcher.end();
            MarkedPassage newPassage = new MarkedPassage(startIndex, endIndex);
            boolean isPartOfMustNot =
                    mustNotPositions.stream().anyMatch(listed -> newPassage.intersects(listed));
            if (!isPartOfMustNot) {
                mustPositions.add(new MarkedPassage(startIndex, endIndex));
                for (TextNode node : getTextNodesBetween(startIndex, endIndex)) {
                    node.wrap(
                            String.format(
                                    "<span style=\"color: %s;\"></span>",
                                    HtmlRFCAnnotation.MUST.getColor()));
                }
            }
        }
        remainingMustAndNot.addAll(mustNotPositions);
        remainingMustAndNot.addAll(mustPositions);
        LOGGER.info(
                "RFC {} contains {} 'MUST's and {} 'MUST NOT's",
                rfcNumber,
                mustPositions.size(),
                mustNotPositions.size());
    }

    public boolean markText(
            String searchText, HtmlRFCAnnotation annotationType, boolean encodeRegex) {
        String pattern = (encodeRegex) ? encodeString(searchText) : searchText;
        pattern = pattern.replace("[The server]", "");
        pattern = pattern.replace("[Servers]", "");
        String[] parts = pattern.split(Pattern.quote("[...]"));
        pattern = parts[parts.length - 1];
        for (String r : "[,],(,),^,$,|,{,}".split(",")) {
            pattern = pattern.replace(r, String.format("\\%s", r));
        }
        pattern = pattern.replaceAll("[\\s\\n]+", "[\\\\s\\\\n]+");

        String text = this.cleanupDoc.getElementsByTag("pre").first().wholeText();
        Matcher matcher = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(text);

        boolean found = false;
        while (matcher.find()) {
            if (found) {
                LOGGER.warn("RFC {}: Multiple matches of '{}'", rfcNumber, searchText);
            }
            found = true;

            int startIndex = matcher.start();
            int endIndex = matcher.end();
            MarkedPassage newPassage = new MarkedPassage(startIndex, endIndex);
            consumeContainedMustAndNot(newPassage, annotationType);
            for (TextNode node : getTextNodesBetween(startIndex, endIndex)) {
                node.wrap(
                        String.format(
                                "<span style=\"color: %s;\"></span>", annotationType.getColor()));
            }
        }

        if (!found) {
            LOGGER.warn("RFC {}: Did not find '{}'", rfcNumber, searchText);
        } else {
            // mark surrounding passages
            for (int i = 0; i < parts.length - 1; i++) {
                if (parts[i].length() > 5) {
                    markText(parts[i], annotationType, false);
                }
            }
        }
        return found;
    }

    public String getHtml() {
        return cleanupDoc.html();
    }

    public void saveToFolder(String folder) {
        String html = getHtml();
        Path target = Paths.get(folder, String.format("%d.html", rfcNumber));
        try {
            Files.createDirectories(Paths.get(folder));
            target.toFile().createNewFile();
            Files.writeString(target, html, StandardOpenOption.WRITE);
        } catch (Exception e) {
            LOGGER.error("error while writing file", e);
        }
    }

    private List<TextNode> getTextNodesBetween(int start, int end) {
        int startIndex = -1;
        int endIndex = -1;
        int i = 0;
        while (i < nodeOffsetIndex.size()) {
            if (startIndex == -1) {
                OffsetTextNode node = nodeOffsetIndex.get(i);
                if (node.getOffset() == start) startIndex = i;
                else if (start < node.getOffset()) {
                    startIndex = i;
                    OffsetTextNode toSplit = nodeOffsetIndex.get(i - 1);
                    TextNode newSplit =
                            toSplit.getTextNode().splitText(start - toSplit.getOffset());
                    nodeOffsetIndex.add(i, new OffsetTextNode(newSplit, start));
                    i += 1;
                } else if (i == nodeOffsetIndex.size() - 1) {
                    OffsetTextNode toSplit = nodeOffsetIndex.get(i);
                    int splitOffset = start - toSplit.getOffset();
                    if (splitOffset > 0) {
                        TextNode newSplit = toSplit.getTextNode().splitText(splitOffset);
                        nodeOffsetIndex.add(i + 1, new OffsetTextNode(newSplit, start));
                        startIndex = i + 1;
                        i += 1;
                    } else {
                        startIndex = i;
                    }
                }
            }
            if (endIndex == -1) {
                OffsetTextNode node = nodeOffsetIndex.get(i);
                if (node.getOffset() == end) {
                    endIndex = i - 1;
                    if (endIndex < 0) endIndex = 0;
                    break;
                }
                if (end < node.getOffset()) {
                    OffsetTextNode toSplit = nodeOffsetIndex.get(i - 1);
                    int splitOffset = end - toSplit.getOffset();
                    endIndex = i - 1;
                    if (splitOffset < toSplit.getTextNode().getWholeText().length()) {
                        TextNode newSplit = toSplit.getTextNode().splitText(splitOffset);
                        nodeOffsetIndex.add(i, new OffsetTextNode(newSplit, end));
                    }
                    break;
                }
                if (i == nodeOffsetIndex.size() - 1) {
                    OffsetTextNode toSplit = nodeOffsetIndex.get(i);
                    int splitOffset = end - toSplit.getOffset();
                    endIndex = i;
                    if (splitOffset < toSplit.getTextNode().getWholeText().length()) {
                        TextNode newSplit = toSplit.getTextNode().splitText(splitOffset);
                        nodeOffsetIndex.add(i + 1, new OffsetTextNode(newSplit, end));
                    }
                    break;
                }
            }
            i += 1;
        }

        Collections.sort(nodeOffsetIndex);

        return nodeOffsetIndex.subList(startIndex, endIndex + 1).stream()
                .map(OffsetTextNode::getTextNode)
                .collect(Collectors.toList());
    }

    private String encodeString(String input) {
        return input.replace("+", "\\+").replace("-", "\\-").replace("’", "'");
    }

    private void consumeContainedMustAndNot(
            MarkedPassage consumingPassage, HtmlRFCAnnotation annotationType) {
        int coveringMustNots = remainingMustAndNot.size();
        mustNotPositions.stream()
                .filter(
                        listed ->
                                (consumingPassage.contains(listed)
                                        && remainingMustAndNot.contains(listed)))
                .forEach(remainingMustAndNot::remove);
        coveringMustNots = coveringMustNots - remainingMustAndNot.size();
        int coveringMusts = remainingMustAndNot.size();
        mustPositions.stream()
                .filter(
                        listed ->
                                (consumingPassage.contains(listed)
                                        && remainingMustAndNot.contains(listed)))
                .forEach(remainingMustAndNot::remove);
        coveringMusts = coveringMusts - remainingMustAndNot.size();
        int previouslyCoveredCountMustNot =
                (annotationMustNotCounter.containsKey(annotationType))
                        ? annotationMustNotCounter.get(annotationType)
                        : 0;
        int previouslyCoveredCountMust =
                (annotationMustCounter.containsKey(annotationType))
                        ? annotationMustCounter.get(annotationType)
                        : 0;
        annotationMustNotCounter.put(
                annotationType, previouslyCoveredCountMustNot + coveringMustNots);
        annotationMustCounter.put(annotationType, previouslyCoveredCountMust + coveringMusts);
    }

    public String getPrintableCounters() {
        for (HtmlRFCAnnotation annotationType : HtmlRFCAnnotation.values()) {
            if (!annotationMustCounter.containsKey(annotationType)) {
                annotationMustCounter.put(annotationType, 0);
            }
            if (!annotationMustNotCounter.containsKey(annotationType)) {
                annotationMustNotCounter.put(annotationType, 0);
            }
        }
        StringBuilder builder = new StringBuilder();
        builder.append("\nCoverable MUSTs\n").append(rfcNumber).append("\n");
        appendCountersForList(builder, mustPositions, annotationMustCounter);

        builder.append("\nCoverable MUST NOTs\n").append(rfcNumber).append("\n");
        appendCountersForList(builder, mustNotPositions, annotationMustNotCounter);
        return builder.toString();
    }

    private void appendCountersForList(
            StringBuilder builder,
            List<MarkedPassage> mandatoryPositions,
            Map<HtmlRFCAnnotation, Integer> annotationCounterMap) {
        int keywordsOverall = 0;
        if (!mandatoryPositions.isEmpty()) {
            // subtract first MUST/MUST NOT from terminology explanation
            keywordsOverall = mandatoryPositions.size() - 1;
        }
        builder.append("Overall: ").append(keywordsOverall).append("\n");

        int keywordsCovered = 0;
        for (HtmlRFCAnnotation annotationType : HtmlRFCAnnotation.values()) {
            if (annotationType != HtmlRFCAnnotation.MUST_NOT
                    && annotationType != HtmlRFCAnnotation.MUST) {
                builder.append(annotationType.name())
                        .append(": ")
                        .append(annotationCounterMap.get(annotationType))
                        .append("\n");
                keywordsCovered += annotationCounterMap.get(annotationType);
            }
        }
        if (keywordsCovered != keywordsOverall) {
            LOGGER.error(
                    "RFC contains {} keywords but {} are covered",
                    keywordsOverall,
                    keywordsCovered);
        }
        // append  effective coverage percentage
        builder.append("Coverage: ");
        if (keywordsOverall == 0) {
            builder.append("-");
        } else {
            float relevantKeywords =
                    keywordsOverall
                            - annotationCounterMap.get(HtmlRFCAnnotation.PROTOCOL_EXTENSION)
                            - annotationCounterMap.get(HtmlRFCAnnotation.DEPRECATED)
                            - annotationCounterMap.get(HtmlRFCAnnotation.CONTRADICTORY);
            float effectivelyCovered =
                    annotationCounterMap.get(HtmlRFCAnnotation.COVERED)
                            + annotationCounterMap.get(HtmlRFCAnnotation.IMPLICIT);
            builder.append(String.format("%.1f", (effectivelyCovered / relevantKeywords) * 100))
                    .append("%");
        }
    }

    public class MarkedPassage {
        private final int startIndex;
        private final int endIndex;

        public MarkedPassage(int startIndex, int endIndex) {
            this.startIndex = startIndex;
            this.endIndex = endIndex;
        }

        public boolean intersects(MarkedPassage other) {
            return (startIndex >= other.startIndex && startIndex <= other.endIndex)
                    || (other.startIndex >= startIndex && other.startIndex <= endIndex);
        }

        public boolean contains(MarkedPassage other) {
            return (other.startIndex >= startIndex && other.startIndex <= endIndex);
        }
    }
}
