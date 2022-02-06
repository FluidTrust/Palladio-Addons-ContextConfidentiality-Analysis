package edu.kit.ipd.sdq.attacksurface.attackdag;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Represents a node of a DAG.
 * 
 * @author ugnwq
 * @version 1.0
 * @param <T> - the {@link NodeContent} implementation 
 */
public class Node<T extends NodeContent<?>> {
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

    /**
     * Adds the given content as a new child node to this node iff it would not create a semantic circle. <br/>
     * See: {@link #wouldCreateSemanticCircle(NodeContent)}
     * 
     * @param childContent
     * @return the child node or {@code null} if the added node content would create a 
     */
    public Node<T> addChild (final T childContent) {
        if (!wouldCreateSemanticCircle(childContent)) {
            final Node<T> ret = new Node<>(Objects.requireNonNull(childContent), this);
            this.childNodes.add(ret);
            return ret;
        }
        return null;
    }

    /**
     * Adds the given content as a new child node to this node iff it would not create a semantic circle. <br/>
     * See: {@link #wouldCreateSemanticCircle(NodeContent)}. <br/>
     * Otherwise {@link #find(NodeContent, Node)}
     * 
     * @param childContent
     * @return the child node or  if the added node content would create a 
     */
    public Node<T> addOrFindChild(T attackStatusDescriptorNodeContent) {
        var childNode = addChild(attackStatusDescriptorNodeContent);
        if (childNode == null) {
            childNode = find(attackStatusDescriptorNodeContent, this);
        }
        return childNode;
    }
    
    /**
     * Determines whether adding the given content for a child node of this node would create a semantic circle,
     * i.e. a circle concerning the contents.
     * 
     * @param childContent - the content of the child node
     * @return whether adding the given content for a child node of this node would create a semantic circle
     */
    public boolean wouldCreateSemanticCircle(final T childContent) {
        Objects.requireNonNull(childContent);
        
        for (var localNode = this; localNode != null; localNode = localNode.getParent()) {
            if (localNode.getContent().equals(childContent)) {
                return true;
            }
        }
        return false;
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
    
    /**
     * Finds the node with the given content under and including the given parent node.
     * 
     * @param nodeContent - the given content
     * @param parentNode - the parent node
     * @return the node with the given content under the given parent node or {@code null} if no such node is found
     */
    public Node<T> find(final T nodeContent, final Node<T> parentNode) {
        final Node<T> toFind = new Node<>(nodeContent, parentNode);
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
    
    @Override
    public String toString() {
        return content.toString() + " | children= " + this.childNodes;
    }
}
