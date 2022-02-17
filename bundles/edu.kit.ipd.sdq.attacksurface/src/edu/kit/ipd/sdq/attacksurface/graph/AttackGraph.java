package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.graph.EndpointPair;
import com.google.common.graph.MutableValueGraph;
import com.google.common.graph.ValueGraphBuilder;

import de.uka.ipd.sdq.identifier.Identifier;

/**
 * Represents a graph saving the compromisation status of the model elements in
 * order to easily find all possible attack paths. <br/>
 * The nodes contain the information about the different model elements and if
 * the node was already visited. <br/>
 * The edges contain the information about the used vulnerabilities and
 * credentials
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackGraph {
    private final AttackStatusNodeContent root;

    private AttackStatusNodeContent selectedNode;

    private MutableValueGraph<AttackStatusNodeContent, AttackStatusEdgeContent> graph;

    public AttackGraph(final Entity rootEntity) {
        Objects.requireNonNull(rootEntity);
        this.root = new AttackStatusNodeContent(rootEntity);
        this.graph = ValueGraphBuilder.directed().allowsSelfLoops(true).build();
        this.graph.addNode(this.root);
        this.selectedNode = this.root;
    }

    public AttackStatusNodeContent getRootNodeContent() {
        return this.root;
    }

    public Set<AttackStatusNodeContent> getChildrenOfNode(final AttackStatusNodeContent nodeContent) {
        return this.graph.successors(nodeContent);
    }

    public Set<AttackStatusNodeContent> getParentsOfNode(final AttackStatusNodeContent nodeContent) {
        return this.graph.predecessors(nodeContent);
    }

    public AttackStatusNodeContent getSelectedNode() {
        return this.selectedNode;
    }

    public void setSelectedNode(final AttackStatusNodeContent node) {
        Objects.requireNonNull(node);
        this.selectedNode = findNode(node);
        if (this.selectedNode == null) {
            throw new IllegalArgumentException("node not selectable, not contained in graph! node= " + node);
        }
    }

    public Set<AttackStatusNodeContent> getCompromisedNodes() {
        return this.graph.nodes().stream().filter(AttackStatusNodeContent::isCompromised).collect(Collectors.toSet());
    }

    private AttackStatusEdge appendEdge(final AttackStatusNodeContent attacked,
            final AttackStatusEdgeContent edgeContent, final AttackStatusNodeContent attacker) {
        final var edge = new AttackStatusEdge(edgeContent, EndpointPair.ordered(attacked, attacker));
        this.graph.putEdgeValue(edge.getNodes(), edge.getContent());
        return edge;
    }

    /**
     * Adds the attack source as a child to the selected node and compromises the
     * selected node.
     * 
     * @param causes       - the causes of the attack
     * @param attackSource - the attack source
     */
    public void compromiseSelectedNode(final Set<CVSurface> causes, final AttackStatusNodeContent attackSource) {
        Objects.requireNonNull(attackSource);

        this.selectedNode.setCompromised(true);
        final var edgeContent = this.graph.edgeValue(EndpointPair.ordered(this.selectedNode, attackSource))
                .orElse(new AttackStatusEdgeContent());
        if (!causes.isEmpty()) {
            final boolean isC = causes.iterator().next().isC();
            if (isC) {
                edgeContent.addSet(causes);
            } else {
                edgeContent.addSet(causes);
            }
        }
        appendEdge(this.selectedNode, edgeContent, attackSource);
    }

    public AttackStatusNodeContent findNode(final AttackStatusNodeContent nodeToFind) {
        return this.graph.nodes().stream().filter(n -> n.equals(nodeToFind)).findAny().orElse(null);
    }

    public AttackStatusNodeContent addOrFindChild(final AttackStatusNodeContent parent,
            final AttackStatusNodeContent nodeToFind) {
        final var foundParent = findNode(parent);
        if (foundParent != null) {
            final var found = this.getChildrenOfNode(foundParent).stream().filter(n -> n.equals(nodeToFind)).findAny()
                    .orElse(null);
            return found != null ? found
                    : appendEdge(parent, new AttackStatusEdgeContent(), nodeToFind).getNodes().target();
        } else {
            // TODO exc or null
            throw new IllegalArgumentException(parent + " not found");
        }
    }

    public void resetVisitations() {
        this.graph.nodes().forEach(n -> n.setVisited(false));
    }

    public List<AttackPathSurface> findAllAttackPaths() { 
        //TODO: in handlers: fix cause finding and adding to set + here or in the end: fix ordering, maybe it is necessary to revert paths in the end 
        
        
        final List<AttackPathSurface> allPaths = new ArrayList<>();

        this.selectedNode = this.root;
        while (!this.selectedNode.isVisited()) {
            if (this.selectedNode.isCompromised()) { //TODO partial paths?
                final var children = getChildrenOfNode(this.selectedNode);
                for (final var child : children) {
                    if (!this.selectedNode.equals(child)) {
                        final var edgeValue = this.graph.edgeValue(this.selectedNode, child).orElse(null);
                        final var edge = new AttackStatusEdge(edgeValue, 
                                EndpointPair.ordered(this.selectedNode, child));
                        addEdge(allPaths, edge);
                        if (child.isCompromised()) {
                            final var selectedNodeBefore = this.selectedNode;
                            this.selectedNode.setVisited(true); // so that circles are not possible
                            this.selectedNode = child;
                            allPaths.addAll(findAllAttackPaths());
                            this.selectedNode = selectedNodeBefore;
                        }
                    }
                }
                
                final var hasSelfLoop = this.graph.hasEdgeConnecting(this.selectedNode, this.selectedNode); 
                if (hasSelfLoop) {
                    final var selfLoopEdgeValue = this.graph.edgeValue(this.selectedNode, this.selectedNode).orElse(null);
                    final var selfLoopEdge = 
                            new AttackStatusEdge(selfLoopEdgeValue, EndpointPair.ordered(this.selectedNode, this.selectedNode));
                    addEdge(allPaths, selfLoopEdge);
                }
                
                
            }
            this.selectedNode.setVisited(true);
        }

        if (this.selectedNode.equals(this.root)) { 
            // only at the end of the recursion
            // remove duplicate paths
            return allPaths.stream().distinct().collect(Collectors.toList());
        }

        return allPaths;
    }
    
    private void addEdge(final List<AttackPathSurface> allPaths, final AttackStatusEdge edge) {
        if (allPaths.isEmpty()) {
            allPaths.add(new AttackPathSurface(Arrays.asList(edge)));
        } else {
            final List<AttackPathSurface> newPaths = new ArrayList<>();
            allPaths.forEach(p -> {
                final boolean isFitting = addEdgeIfFitting(p, edge);
                if (!isFitting) {
                    newPaths.add(new AttackPathSurface(Arrays.asList(edge)));
                }
                //TODO consider parts of paths (shorter paths)
            });
            allPaths.addAll(newPaths);
        }
    }

    private boolean addEdgeIfFitting(final AttackPathSurface path, final AttackStatusEdge edge) {
        final boolean isFitting = path.get(path.size() - 1) //TODO look if to reverse in the end
                .getNodes().target()
                .getContainedElement().getId()
                .equals(edge.getNodes().source().getContainedElement().getId());
        
        if (isFitting) {
            path.add(edge);
        }
        return isFitting;
    }

    public boolean isAnyCompromised(Entity... entities) {
        final var compromisedIds = getCompromisedNodes().stream().map(n -> n.getContainedElement().getId())
                .collect(Collectors.toSet());
        for (final var entity : entities) {
            if (compromisedIds.contains(entity.getId())) {
                return true;
            }
        }
        return false;
    }
}
