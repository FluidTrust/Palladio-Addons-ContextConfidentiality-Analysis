package edu.kit.ipd.sdq.attacksurface.attackdag;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public class AttackDAG { // it is even a tree
    private final Node<AttackStatusDescriptorNodeContent> rootNode;
    
    /*
     * node for finding a node (context in which the find method should search)
     */
    private Node<AttackStatusDescriptorNodeContent> contextParentNode;
    
    public AttackDAG(final AssemblyContext criticalAssembly) { //TODO adapt: more general (see core main)
        this.rootNode = new Node<AttackStatusDescriptorNodeContent>(
                new AttackStatusDescriptorNodeContent(criticalAssembly), null);
    }
    
    public Node<AttackStatusDescriptorNodeContent> getRootNode() {
        return this.rootNode;
    }
    
    public boolean isRootNodeCompromised() {
        return this.rootNode.getContent().isCompromised();
    }
    
    public void addToContextParentNode(final AttackStatusDescriptorNodeContent newChildNodeContent) {
        if (this.contextParentNode == null) {
            return; //TODO maybe exc
        }
        this.contextParentNode.addChild(newChildNodeContent);
    }

    public void setContextParentNode(Node<AttackStatusDescriptorNodeContent> contextParentNode) {
        this.contextParentNode = contextParentNode;
    }

    public boolean contains(final AttackStatusDescriptorNodeContent nodeContent) { //TODO s. above
        return this.rootNode.contains(nodeContent);
    }
    
    public Node<AttackStatusDescriptorNodeContent> find(final AttackStatusDescriptorNodeContent nodeContent) {
        return this.rootNode.find(nodeContent, this.contextParentNode);
    }
    
    //TODO v maybe not public
    public Node<AttackStatusDescriptorNodeContent> find(final AttackStatusDescriptorNodeContent nodeContent, 
            final Node<AttackStatusDescriptorNodeContent> parentNode) {
        return this.rootNode.find(nodeContent, parentNode);
    }
    
    
}
