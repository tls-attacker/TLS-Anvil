/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.extractor;


import org.jsoup.nodes.TextNode;

public class OffsetTextNode implements Comparable<OffsetTextNode> {
    private TextNode textNode;
    private Integer offset;

    public OffsetTextNode(TextNode node, Integer offset) {
        this.textNode = node;
        this.offset = offset;
    }

    public TextNode getTextNode() {
        return textNode;
    }

    public void setTextNode(TextNode textNode) {
        this.textNode = textNode;
    }

    public Integer getOffset() {
        return offset;
    }

    public void setOffset(Integer offset) {
        this.offset = offset;
    }


    @Override
    public int compareTo(OffsetTextNode o) {
        return this.offset.compareTo(o.offset);
    }

    @Override
    public String toString() {
        return String.format("[Offset=%d, Text='%s']", offset, textNode.getWholeText());
    }
}
