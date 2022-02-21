package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.graph.EndpointPair;
import com.google.common.graph.MutableValueGraph;
import com.google.common.graph.Traverser;
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
            edgeContent.addSet(causes);
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

    public Set<String> getCompromisationCauseIds(final AttackStatusNodeContent node) {
        return this.graph.edges().stream().filter(e -> e.source().equals(node)).map(e -> this.graph.edgeValue(e))
                .map(e -> e.orElse(null)).filter(Objects::nonNull).map(AttackStatusEdgeContent::getCauseIds)
                .flatMap(Set::stream).collect(Collectors.toSet());
    }

    public List<AttackPathSurface> findAllAttackPaths() {
        final List<AttackPathSurface> allPaths = new ArrayList<>();

        Traverser<AttackStatusNodeContent> traverser = Traverser.forGraph(this.graph);
        final var bfsIterable = traverser.depthFirstPreOrder(this.root);
        for (final var nodeContent : bfsIterable) {
            if (nodeContent.isCompromised()) {
                // TODO remove > final int level = getLevel(nodeContent);
                
                final var children = this.getChildrenOfNode(nodeContent);
                for (final var child : children) {
                    final var edgeValue = this.graph.edgeValue(nodeContent, child).orElse(null);
                    final var edge = new AttackStatusEdge(edgeValue, EndpointPair.ordered(nodeContent, child));
                    final boolean isAttackerCompromised = child.isCompromised();
                    addEdge(allPaths, edge, isAttackerCompromised);
                }
            }
        }

        // remove duplicate paths
        // and partial paths (??) TODO
        return allPaths.stream()
                .distinct()
                .filter(p -> !p.isEmpty())
                .filter(p -> p.get(p.size() - 1).getNodes().target().equals(this.root)) //TODO
                .collect(Collectors.toList());
    }

    /*TODO remove private int getLevel(final AttackStatusNodeContent node) {
        if (node.equals(this.root)) {
            return 0;
        }
        var parents = this.getParentsOfNode(node);
        if (parents.contains(this.root)) {
            return 1;
        } else {
            int minLevel = Integer.MAX_VALUE;
            for (final var parent : parents) {
                final var getLevelResult = getLevel(parent);
                final var level = 1 + getLevelResult;
                if (level < minLevel) {
                    minLevel = level;
                }
                if (getLevelResult == 1) {
                    return minLevel;
                }
            }
            return minLevel;
        }
    }*/

    private void addEdge(final List<AttackPathSurface> allPaths, final AttackStatusEdge edge,
            final boolean isAttackerCompromised) {
        if (allPaths.isEmpty()) {
            allPaths.add(new AttackPathSurface(Arrays.asList(edge.createReverseEdge())));
        } else if (!isAttackerCompromised || !areCauseSetsEmpty(edge)) {
            final List<AttackPathSurface> newPaths = new ArrayList<>();
            allPaths.forEach(p -> {
                final var pathCopy = p.getCopy();
                final boolean isFitting = addEdgeIfFitting(p, edge.createReverseEdge());
                if (isFitting) {
                    newPaths.add(pathCopy);
                }
            });
            allPaths.addAll(newPaths);
        }
    }

    private boolean areCauseSetsEmpty(AttackStatusEdge edge) {
        boolean ret = !edge.getContent().getContainedSetCIterator().hasNext() 
                && !edge.getContent().getContainedSetVIterator().hasNext();
        
        if (!ret) {
            final var cIter = edge.getContent().getContainedSetCIterator();
            while (cIter.hasNext()) {
                final var set = cIter.next();
                ret = set.isEmpty();
                if (!ret) {
                    return false;
                }
            }
            final var vIter = edge.getContent().getContainedSetVIterator();
            while (vIter.hasNext()) {
                final var set = vIter.next();
                ret = set.isEmpty();
                if (!ret) {
                    return false;
                }
            }
        }
        
        return ret;
    }

    private boolean addEdgeIfFitting(final AttackPathSurface path, final AttackStatusEdge edge) {
        final boolean isFitting = path.get(0).getNodes().source().equals(edge.getNodes().target());

        if (isFitting) {
            path.addFirst(edge);
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
