package edu.kit.ipd.sdq.attacksurface.attackdag;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

/**
 * Represents a DAG, even a tree for saving the compromisation status of the model elements in order
 * to easily find all possible attack paths. 
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackDAG {
    private final Node<AttackStatusDescriptorNodeContent> rootNode;

    private Node<AttackStatusDescriptorNodeContent> selectedNode;
    
    private Set<AttackPathSurface> alreadyFoundPaths;

    /**
     * Creates a new {@link AttackDAG} for the given root critical entity.
     *  
     * @param rootAssembly - the root entity
     */
    public AttackDAG(final Entity rootEntity) {
        this.rootNode = new Node<AttackStatusDescriptorNodeContent>(new AttackStatusDescriptorNodeContent(rootEntity),
                null);
        this.selectedNode = this.rootNode;
        this.alreadyFoundPaths = new HashSet<>();
    }

    /**
     * 
     * @return the root node (critical element descriptor)
     */
    public Node<AttackStatusDescriptorNodeContent> getRootNode() {
        return this.rootNode;
    }

    /**
     * 
     * @return determines whether the root node is compromised
     */
    public boolean isRootNodeCompromised() {
        return this.rootNode.getContent().isCompromised();
    }

    /**
     * 
     * @return gets the currently selected node
     * @see #setSelectedNode(Node)
     */
    public Node<AttackStatusDescriptorNodeContent> getSelectedNode() {
        return this.selectedNode;
    }

    /**
     * Sets the given node as selected.
     * 
     * @param selectedNode - the given node
     * @see #getSelectedNode()
     */
    public void setSelectedNode(Node<AttackStatusDescriptorNodeContent> selectedNode) {
        this.selectedNode = selectedNode;
    }

    /**
     * 
     * @return gets the set of already found paths
     * @see #addAlreadyFoundPath(AttackPathSurface)
     */
    public Set<AttackPathSurface> getAlreadyFoundPaths() {
        return Collections.unmodifiableSet(this.alreadyFoundPaths
                .stream()
                .map(AttackPathSurface::getUnmodifiableCopy)
                .collect(Collectors.toSet()));
    }

    /**
     * 
     * @param path - the path list containing of {@link AttackStatusDescriptorNodeContent}
     */
    public void addAlreadyFoundPath(final AttackPathSurface path) {
        this.alreadyFoundPaths.add(path);
    }

    /**
     * Determines whether the given {@link AttackStatusDescriptorNodeContent} is contained in the DAG. 
     * 
     * @param nodeContent - the given node content
     * @return whether the given node content is contained
     */
    public boolean contains(final AttackStatusDescriptorNodeContent nodeContent) {
        return this.rootNode.contains(nodeContent);
    }
    
    //TODO maybe remove these methods v
    /**
     * 
     * @param nodeContent
     * @return
     */
    public Node<AttackStatusDescriptorNodeContent> find(final AttackStatusDescriptorNodeContent nodeContent) {
        return find(nodeContent, this.selectedNode);
    }

    private Node<AttackStatusDescriptorNodeContent> find(final AttackStatusDescriptorNodeContent nodeContent,
            final Node<AttackStatusDescriptorNodeContent> parentNode) {
        return this.rootNode.find(nodeContent, parentNode);
    }
    
    @Override
    public String toString() {
        return this.rootNode.toString();
    }

}
