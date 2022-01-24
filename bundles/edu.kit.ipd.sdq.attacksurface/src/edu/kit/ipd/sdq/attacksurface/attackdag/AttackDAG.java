package edu.kit.ipd.sdq.attacksurface.attackdag;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public class AttackDAG { // it is even a tree
    private final Node<AttackStatusDescriptorNodeContent> rootNode;

    private Node<AttackStatusDescriptorNodeContent> selectedNode;
    private Set<List<AttackStatusDescriptorNodeContent>> alreadyFoundPaths;

    public AttackDAG(final AssemblyContext rootAssembly) { // TODO adapt: more general (see core main)
        this.rootNode = new Node<AttackStatusDescriptorNodeContent>(new AttackStatusDescriptorNodeContent(rootAssembly),
                null);
        this.selectedNode = this.rootNode;
        this.alreadyFoundPaths = new HashSet<>();
    }

    public Node<AttackStatusDescriptorNodeContent> getRootNode() {
        return this.rootNode;
    }

    public boolean isRootNodeCompromised() {
        return this.rootNode.getContent().isCompromised();
    }

    public Node<AttackStatusDescriptorNodeContent> getSelectedNode() {
        return this.selectedNode;
    }

    public void setSelectedNode(Node<AttackStatusDescriptorNodeContent> selectedNode) {
        this.selectedNode = selectedNode;
    }

    public Set<List<AttackStatusDescriptorNodeContent>> getAlreadyFoundPaths() {
        return Collections.unmodifiableSet(this.alreadyFoundPaths
                .stream()
                .map(Collections::unmodifiableList)
                .collect(Collectors.toSet()));
    }

    public void addAlreadyFoundPath(final List<AttackStatusDescriptorNodeContent> path) {
        this.alreadyFoundPaths.add(path);
    }

    public boolean contains(final AttackStatusDescriptorNodeContent nodeContent) {
        return this.rootNode.contains(nodeContent);
    }

    public Node<AttackStatusDescriptorNodeContent> find(final AttackStatusDescriptorNodeContent nodeContent) {
        return find(nodeContent, this.selectedNode);
    }

    private Node<AttackStatusDescriptorNodeContent> find(final AttackStatusDescriptorNodeContent nodeContent,
            final Node<AttackStatusDescriptorNodeContent> parentNode) {
        return this.rootNode.find(nodeContent, parentNode);
    }

}
