package edu.kit.ipd.sdq.attacksurface.attackdag;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public class AttackDAG { // it is even a tree
    private final Node<AttackStatusDescriptorNodeContent> rootNode;
    
    private Node<AttackStatusDescriptorNodeContent> selectedNode;
    
    public AttackDAG(final AssemblyContext criticalAssembly) { //TODO adapt: more general (see core main)
        this.rootNode = new Node<AttackStatusDescriptorNodeContent>(
                new AttackStatusDescriptorNodeContent(criticalAssembly), null);
        this.selectedNode = this.rootNode;
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
