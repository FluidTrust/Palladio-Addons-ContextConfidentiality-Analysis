package edu.kit.ipd.sdq.attacksurface.attackdag;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class Node<T extends NodeContent> {
    private final T content;
    private final Node<T> parent;
    private final List<Node<T>> childNodes;
    
    Node(final T content, final Node<T> parent) {
        this.content = Objects.requireNonNull(content);
        this.parent = parent;
        this.childNodes = new ArrayList<>();
    }
    
    public T getContent() {
        return this.content;
    }

    public void addChild (T childContent) {
        this.childNodes.add(new Node<T>(Objects.requireNonNull(childContent), this));
    }
    
    public boolean isRoot() {
        return this.parent == null;
    }
    
    public Node<T> getParent() {
        return this.parent;
    }
    
    public List<Node<T>> getChildNodes() {
        return Collections.unmodifiableList(this.childNodes);
    }
    
    public boolean contains(final T nodeContent) {
        return content.equals(nodeContent) || 
                getChildNodes().stream().anyMatch(n -> n.contains(nodeContent));
    }
    
    public Node<T> find(final T nodeContent, final Node<T> parentNode) {
        final Node<T> toFind = new Node<T>(nodeContent, parentNode);
        if (this.equals(toFind)) {
            return this;
        }
        return getChildNodes()
                .stream()
                .filter(n -> n.equals(toFind))
                .findAny()
                .orElse(null);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(this.content, this.parent);
    }
    
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null) {
            return false;
        }
        if (other instanceof Node) {
            final Node<?> otherNode = (Node<?>)other;
            return otherNode.content.equals(this.content) 
                    && Objects.equals(otherNode.parent, this.parent);
        }
        return false;
    }
}
