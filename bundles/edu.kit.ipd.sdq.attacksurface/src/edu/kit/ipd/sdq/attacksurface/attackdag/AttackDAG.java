package edu.kit.ipd.sdq.attacksurface.attackdag;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public class AttackDAG { // it is even a tree
    private final Node<AttackStatusDescriptorNodeContent> rootNode;

    private Node<AttackStatusDescriptorNodeContent> selectedNode;
    private List<List<Node<AttackStatusDescriptorNodeContent>>> subPaths;

    public AttackDAG(final AssemblyContext rootAssembly) { // TODO adapt: more general (see core main)
        this.rootNode = new Node<AttackStatusDescriptorNodeContent>(new AttackStatusDescriptorNodeContent(rootAssembly),
                null);
        this.selectedNode = this.rootNode;
        this.subPaths = new ArrayList<>();
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

    public List<List<Node<AttackStatusDescriptorNodeContent>>> getSubPaths() {
        return Collections.unmodifiableList(this.subPaths
                .stream()
                .map(Collections::unmodifiableList)
                .collect(Collectors.toList()));
    }

    public void addNodeToSubPath(final int index, final Node<AttackStatusDescriptorNodeContent> nodeToAdd) {
        while (this.subPaths.size() <= index) {
            this.subPaths.add(new ArrayList<>());
        }
        this.subPaths.get(index).add(nodeToAdd);
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
