package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.graph.EndpointPair;
import com.google.common.graph.Graphs;
import com.google.common.graph.MutableValueGraph;
import com.google.common.graph.Traverser;
import com.google.common.graph.ValueGraphBuilder;

import de.uka.ipd.sdq.identifier.Identifier;
import edu.kit.ipd.sdq.attacksurface.core.AttackHandlingHelper;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Represents a graph saving the compromisation status of the model elements in
 * order to easily find all possible attack paths. <br/>
 * The nodes contain the information about the different model elements and if
 * the node was already visited. <br/>
 * The edges contain the information about the used vulnerabilities and
 * credentials.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackGraph {
    private final AttackStatusNodeContent root;
    private final MutableValueGraph<AttackStatusNodeContent, AttackStatusEdgeContent> graph;

    private AttackStatusNodeContent selectedNode;
    
    /**
     * Creates a new {@link AttackGraph} with the given entity as the root entity, i.e. critical element.
     * 
     * @param rootEntity - the given critical entity
     */
    public AttackGraph(final Entity rootEntity) {
        Objects.requireNonNull(rootEntity);
        this.root = new AttackStatusNodeContent(rootEntity);
        this.graph = ValueGraphBuilder.directed().allowsSelfLoops(true).build();
        this.graph.addNode(this.root);
        this.selectedNode = this.root;
    }

    private AttackGraph(AttackStatusNodeContent root,
            MutableValueGraph<AttackStatusNodeContent, AttackStatusEdgeContent> copyGraph) {
        this.graph = copyGraph;
        this.root = findNode(root);
        this.selectedNode = this.root;
    }

    /**
     * 
     * @return the root node, i.e. the critical entity
     */
    public AttackStatusNodeContent getRootNodeContent() {
        return this.root;
    }

    /**
     * Gets all children of the given parent node, i.e. all nodes that are possible attackers
     * of the given parent node.
     * 
     * @param nodeContent - the parent node
     * @return the children of the parent node and the parent node itself iff there is a self loop
     */
    public Set<AttackStatusNodeContent> getChildrenOfNode(final AttackStatusNodeContent nodeContent) {
        return this.graph.successors(nodeContent);
    }

    /**
     * Gets the parents of the given child node, i.e. all nodes that are potentially attackable from
     * the given child node.
     * 
     * @param nodeContent - the given child node
     * @return the child nodes
     */
    public Set<AttackStatusNodeContent> getParentsOfNode(final AttackStatusNodeContent nodeContent) {
        return this.graph.predecessors(nodeContent);
    }

    /**
     * 
     * @return the selected node at the moment
     */
    public AttackStatusNodeContent getSelectedNode() {
        return this.selectedNode;
    }

    /**
     * Sets the selected node to the given one.
     * 
     * @param node - the node to be set as the selected node (it must be contained in the path)
     */
    public void setSelectedNode(final AttackStatusNodeContent node) {
        Objects.requireNonNull(node);
        this.selectedNode = findNode(node);
        if (this.selectedNode == null) {
            throw new IllegalArgumentException("node not selectable, not contained in graph! node= " + node);
        }
    }

    /**
     * 
     * @return all compromised nodes
     */
    public Set<AttackStatusNodeContent> getCompromisedNodes() {
        return this.graph.nodes().stream().filter(AttackStatusNodeContent::isCompromised).collect(Collectors.toSet());
    }
    
    /**
     * 
     * @return all attacked nodes
     */
    public Set<AttackStatusNodeContent> getAttackedNodes() {
        return this.graph.nodes().stream().filter(AttackStatusNodeContent::isAttacked).collect(Collectors.toSet());

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
    


    /**
     * Attacks the given nodes with a self edge with the given set of vulnerabilities, not 
     * taking over the node.
     * 
     * @param attackedNodes
     * @param vulnerabilities
     */
    public void attackNodesWithVulnerabilities(Collection<AttackStatusNodeContent> attackedNodes,
            Set<Vulnerability> vulnerabilities) {
        for (final var attacked : attackedNodes) {
            attacked.setAttacked(true);
            final var edgeNow = getEdge(attacked, attacked);
            final var content = edgeNow != null ? edgeNow : new AttackStatusEdgeContent();
            final Set<CVSurface> surfaceSet = vulnerabilities
                    .stream()
                    .map(Identifier::getId)
                    .map(VulnerabilitySurface::new)
                    .collect(Collectors.toSet());
            content.addSetV(surfaceSet);
            this.appendEdge(attacked, content, attacked);
        }
    }

    /**
     * Finds the given node inside the graph.
     * 
     * @param nodeToFind - a {@link AttackStatusNodeContent} containing the entity to be found in the graph
     * @return the found node containing the entity contained in the parameter
     */
    public AttackStatusNodeContent findNode(final AttackStatusNodeContent nodeToFind) {
        return this.graph.nodes().stream().filter(n -> n.equals(nodeToFind)).findAny().orElse(null);
    }

    /**
     * Finds the node in the graph or otherwise adds it with an empty edge (containing no attack causes yet).
     * 
     * @param parent - the parent node (must already be findable inside the graph)
     * @param nodeToFind - the node to be found or added
     * @return the found or added node
     * 
     * @see #findNode(AttackStatusNodeContent)
     */
    public AttackStatusNodeContent addOrFindChild(final AttackStatusNodeContent parent,
            final AttackStatusNodeContent nodeToFind) {
        final var foundParent = findNode(parent);
        if (foundParent != null) {
            final var found = this.getChildrenOfNode(foundParent).stream().filter(n -> n.equals(nodeToFind)).findAny()
                    .orElse(null);
            return found != null ? found
                    : appendEdge(parent, new AttackStatusEdgeContent(), nodeToFind).getNodes().target();
        } else {
            throw new IllegalArgumentException(parent + " not found");
        }
    }

    /**
     * Resets the visitationm status or all nodes inside the graph to {@code false}.
     */
    public void resetVisitations() {
        this.graph.nodes().forEach(n -> n.setVisited(false));
    }

    /**
     * Gets all compromisation cause IDs of the given node.
     * 
     * @param node - the given node
     * @return all compromisation cause IDs of the given node
     */
    public Set<String> getCompromisationCauseIds(final AttackStatusNodeContent node) {
        return this.graph.edges()
                .stream()
                .filter(e -> e.source().equals(node))
                .map(this.graph::edgeValue)
                .map(e -> e.orElse(null)).filter(Objects::nonNull)
                .map(AttackStatusEdgeContent::getCauseIds)
                .flatMap(Set::stream).collect(Collectors.toSet());
    }

    /**
     * Finds all possible attack paths in this graph. <br />
     * Additionally, paths with initially necessary 
     * 
     * @param board - the model storage
     * @param changes - the changes
     * @return all possible attack paths
     */
    public List<AttackPathSurface> findAllAttackPaths(final BlackboardWrapper board, final CredentialChange changes) {
        List<AttackPathSurface> allPaths = new ArrayList<>();
        
        Traverser<AttackStatusNodeContent> traverser = Traverser.forGraph(copy().graph);
        final var dfsIterable = traverser.depthFirstPreOrder(this.root);
        boolean isChanged = false;
        for (final var nodeContentToFind : dfsIterable) {
            final var node = findNode(nodeContentToFind);
            isChanged |= attackNodeContentWithInitialCredentialIfNecessary(board, node, changes);
            if (node.isAttacked()) {
                final var children = this.getChildrenOfNode(node);
                for (final var child : children) {
                    final var edgeValue = this.graph.edgeValue(node, child).orElse(null);
                    final var edge = new AttackStatusEdge(edgeValue, EndpointPair.ordered(node, child));
                    addEdge(allPaths, edge);
                }
            }
        }
        if (isChanged) {
            allPaths = findAllAttackPaths(board, changes)
                    .stream()
                    .filter(AttackPathSurface::containsInitiallyNecessaryCredentials)
                    .collect(Collectors.toList());
        }
        // remove duplicate paths and partial paths
        return allPaths.stream()
                .distinct()
                .filter(p -> !p.isEmpty())
                .filter(p -> p.get(p.size() - 1).getNodes().target().equals(this.root))
                .map(AttackPathSurface::fillCredentialsInitiallyNecessary)
                .collect(Collectors.toList());
    }
    
    private AttackGraph copy() {
        final var copyGraph = Graphs.copyOf(this.graph);
        return new AttackGraph(this.root, copyGraph);
    }

    private boolean attackNodeContentWithInitialCredentialIfNecessary(final BlackboardWrapper board,
            final AttackStatusNodeContent node, final CredentialChange changes) {
        final boolean isCompromised = 
                AttackHandlingHelper.attackNodeContentWithInitialCredentialIfNecessary(
                        board, this, node);
        if (isCompromised && node.getTypeOfContainedElement().equals(PCMElementType.RESOURCE_CONTAINER)) {
            final var dataHandler =  new DataHandlerAttacker(changes);
            final var attackInnerHandler = new AssemblyContextContext(board, dataHandler, this);
            attackInnerHandler.attackAssemblyContext(getContainedComponents(node), changes, 
                    node.getContainedElement(), true);
        }
        return isCompromised;
    }

    private List<AssemblyContext> getContainedComponents(AttackStatusNodeContent containerNode) {
        return this.getParentsOfNode(containerNode)
                .stream()
                .filter(n -> n.getTypeOfContainedElement().equals(PCMElementType.ASSEMBLY_CONTEXT))
                .map(n -> n.getContainedElementAsPCMElement().getAssemblycontext())
                .collect(Collectors.toList());
    }

    private void addEdge(final List<AttackPathSurface> allPaths, final AttackStatusEdge edge) {
        final var reverseEdge = edge.createReverseEdge();
        final var edgePath = reverseEdge.toPath();
        if (allPaths.isEmpty()) {
            allPaths.add(edgePath);
        } else {
            final List<AttackPathSurface> newPaths = new ArrayList<>();
            allPaths.forEach(p -> {
                final var pathCopy = p.getCopy();
                final boolean isFitting = addEdgeIfFitting(p, reverseEdge);
                final boolean isEdgeSimplePath = reverseEdge.getNodes().target()
                        .equals(this.root);
                if (isFitting) {
                    newPaths.add(pathCopy);
                }
                if (isEdgeSimplePath) {
                    newPaths.add(edgePath);
                }
            });
            allPaths.addAll(newPaths);
        }
    }

    private boolean addEdgeIfFitting(final AttackPathSurface path, final AttackStatusEdge edge) {
        final boolean isFitting = path.get(0).getNodes().source().equals(edge.getNodes().target());

        if (isFitting) {
            path.addFirst(edge);
        }
        return isFitting;
    }
    
    /**
     * Gets the {@link AttackStatusEdgeContent} between the attacked node and the 
     * attacker node if it already exists, {@code null} otherwise
     * 
     * @param start - the source node in the attack graph, i.e. the attacked node
     * @param end - the targe node in the attack graph, i.e. the attacker node
     * @return the {@link AttackStatusEdgeContent} between the attacked node and the 
     * attacker node if it already exists, {@code null} otherwise
     */
    public AttackStatusEdgeContent getEdge(final AttackStatusNodeContent start, 
            final AttackStatusNodeContent end) {
        final var opt = this.graph.edges()
                .stream()
                .filter(e -> e.source().equals(start))
                .filter(e -> e.target().equals(end))
                .map(this.graph::edgeValue)
                .findFirst().orElse(null);
        return opt != null ? opt.orElse(null) : null;
    }

    /**
     * 
     * @param edgeEnds - the edge ends
     * @return the {@link AttackStatusEdgeContent} between the attacked node and the 
     * attacker node if it already exists, {@code null} otherwise
     * @see #getEdge(AttackStatusNodeContent, AttackStatusNodeContent)
     */
    public AttackStatusEdgeContent getEdge(final EndpointPair<AttackStatusNodeContent> edgeEnds) {
        return getEdge(edgeEnds.source(), edgeEnds.target());
    }

    /**
     * 
     * @param entities - the given entities
     * @return whether any of the given entities is compromised
     */
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

    /**
     * 
     * @return all the node in the graph
     */
    public Set<AttackStatusNodeContent> getNodes() {
        return this.graph.nodes();
    }
    
    /**
     * 
     * @return all the edges in the graph
     */
    public Set<AttackStatusEdge> getEdges() {
        final var ret = new HashSet<AttackStatusEdge>();
        final var edgeEndpointSet = this.graph.edges();
        for (final var edgeEnds : edgeEndpointSet) {
            ret.add(new AttackStatusEdge(getEdge(edgeEnds), edgeEnds));
        }
        return ret;
    }
}
