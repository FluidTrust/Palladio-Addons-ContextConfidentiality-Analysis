package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.graph.EndpointPair;
import com.google.common.graph.ImmutableNetwork;
import com.google.common.graph.MutableValueGraph;
import com.google.common.graph.ValueGraphBuilder;

import de.uka.ipd.sdq.identifier.Identifier;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

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
public class AttackGraph implements AttackPathFinder {
    private AttackNodeContent root;
    private MutableValueGraph<AttackNodeContent, AttackStatusEdgeContent> graph;

    private AttackNodeContent selectedNode;
    private AttackPathSurface selectedPath;

    private final Map<VulnerabilitySurface, Set<CredentialSurface>> credentialsObtainedByAttack;
    private final Map<AttackStatusEdge, Set<VulnerabilitySurface>> attackEdgesToCredentialGainingVulnerabilitiesMap;
    private final Set<CredentialSurface> credentialsFromBeginningOn;

    private final AttackPathFinder finder;

    /**
     * Creates a new {@link AttackGraph} with the given entity as the root entity,
     * i.e. critical element.
     *
     * @param rootEntity - the given critical entity
     */
    public AttackGraph(final Entity rootEntity) {
        initializeGraph(rootEntity);
        this.credentialsObtainedByAttack = new HashMap<>();
        this.attackEdgesToCredentialGainingVulnerabilitiesMap = new HashMap<>();
        this.credentialsFromBeginningOn = new HashSet<>();

        this.finder = new DefaultAttackPathFinder(this);
    }

    /**
     * Copy constructor for attack path generation.
     *
     * @param root - the root node
     * @param copyGraph - the copied graph
     */
    AttackGraph(AttackNodeContent root,
            MutableValueGraph<AttackNodeContent, AttackStatusEdgeContent> copyGraph) {
        this.graph = copyGraph;
        this.root = findNode(root);
        this.selectedNode = this.root;
        this.credentialsObtainedByAttack = new HashMap<>();
        this.attackEdgesToCredentialGainingVulnerabilitiesMap = new HashMap<>();
        this.credentialsFromBeginningOn = new HashSet<>();

        this.finder = new DefaultAttackPathFinder(this);
    }

    private void initializeGraph(final Entity rootEntity) {
        Objects.requireNonNull(rootEntity);
        this.root = new AttackNodeContent(rootEntity);
        this.graph = ValueGraphBuilder.directed().allowsSelfLoops(true).build();
        getGraph().addNode(this.root);
        this.selectedNode = findNode(this.root);
    }

    /**
     *
     * @return the root node, i.e. the critical entity
     */
    public AttackNodeContent getRootNodeContent() {
        return this.root;
    }

    /**
     *
     * @return the graph for the attack path finder
     */
    MutableValueGraph<AttackNodeContent, AttackStatusEdgeContent> getGraph() {
        return this.graph;
    }

    /**
     * Gets all children of the given parent node, i.e. all nodes that are possible
     * attackers of the given parent node.
     *
     * @param nodeContent - the parent node
     * @return the children of the parent node and the parent node itself iff there
     *         is a self loop
     */
    public Set<AttackNodeContent> getChildrenOfNode(final AttackNodeContent nodeContent) {
        return getGraph().successors(nodeContent);
    }

    /**
     * Gets the parents of the given child node, i.e. all nodes that are potentially
     * attackable from the given child node.
     *
     * @param nodeContent - the given child node
     * @return the child nodes
     */
    public Set<AttackNodeContent> getParentsOfNode(final AttackNodeContent nodeContent) {
        return getGraph().predecessors(nodeContent);
    }

    /**
     *
     * @return the selected node at the moment
     */
    public AttackNodeContent getSelectedNode() {
        return this.selectedNode;
    }

    /**
     *
     * @return the selected path at the moment
     */
    public AttackPathSurface getSelectedPath() {
        return this.selectedPath;
    }

    /**
     *
     * @param selectedPath - the selected path at the moment
     */
    public void setSelectedPath(AttackPathSurface selectedPath) {
        this.selectedPath = selectedPath;
    }

    /**
     *
     * @param localAttackEdge - the local attack edge
     * @param alsoConsiderPath - if the selected path should be considered as well
     * @return the credentials obtained on the selected path by vulnerabilities
     */
    public Set<CredentialSurface> getCredentials(final AttackStatusEdge localAttackEdge,
            final boolean alsoConsiderPath) {
        final Set<CredentialSurface> ret = new HashSet<>(this.credentialsFromBeginningOn);
        if (this.selectedPath == null) {
            return ret;
        }
        final var localPath = alsoConsiderPath ? this.selectedPath.getCopy()
                : new AttackPathSurface();
        localPath.addFirst(localAttackEdge);
        ret.addAll(localPath
                    .stream()
                    .map(this::getByTargetNode)
                    .filter(Objects::nonNull)
                    .flatMap(Set::stream)
                    .map(this.credentialsObtainedByAttack::get)
                    .filter(Objects::nonNull)
                    .flatMap(Set::stream)
                    .collect(Collectors.toSet()));
        return ret;
    }

    private Set<VulnerabilitySurface> getByTargetNode(AttackStatusEdge edge) {
        final var ret = this.attackEdgesToCredentialGainingVulnerabilitiesMap.get(edge);
        if (ret == null) {
            return this.attackEdgesToCredentialGainingVulnerabilitiesMap.keySet().stream()
                    .filter(e -> {
                        final var target = e.getNodes().target();
                        return target.equals(edge.getNodes().source()) ||
                            target.equals(edge.getNodes().target());
                     })
                    .map(this.attackEdgesToCredentialGainingVulnerabilitiesMap::get)
                    .flatMap(Set::stream)
                    .collect(Collectors.toSet());
        }
        return ret;
    }

    /**
     *
     * @param credentials - the credentials to be available in every path
     */
    public void addCredentialsFromBeginningOn(final Set<CredentialSurface> credentials) {
        this.credentialsFromBeginningOn.addAll(credentials);
    }

    /**
     * Sets the selected node to the given one.
     *
     * @param node - the node to be set as the selected node (it must be contained
     *             in the graph)
     */
    public void setSelectedNode(final AttackNodeContent node) {
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
    public Set<AttackNodeContent> getCompromisedNodes() {
        return getGraph().nodes().stream().filter(AttackNodeContent::isCompromised).collect(Collectors.toSet());
    }

    /**
     *
     * @return all attacked nodes
     */
    public Set<AttackNodeContent> getAttackedNodes() {
        return getGraph().nodes().stream().filter(AttackNodeContent::isAttacked).collect(Collectors.toSet());

    }

    private AttackStatusEdge appendEdge(final AttackNodeContent attacked,
            final AttackStatusEdgeContent edgeContent, final AttackNodeContent attacker) {
        final var edge = new AttackStatusEdge(edgeContent, EndpointPair.ordered(attacked, attacker));
        getGraph().putEdgeValue(edge.getNodes(), edge.getContent());
        return edge;
    }

    /**
     * Adds the attack source as a child to the selected node and compromises the
     * selected node.
     *
     * @param causes       - the causes of the attack
     * @param attackSource - the attack source
     */
    public void compromiseSelectedNode(final Set<? extends CredentialsVulnearbilitiesSurface> causes,
            final AttackNodeContent attackSource) {
        Objects.requireNonNull(attackSource);

        this.selectedNode.compromise(attackSource);
        final var edgeContent = getGraph().edgeValue(EndpointPair.ordered(this.selectedNode, attackSource))
                .orElse(new AttackStatusEdgeContent());
        if (!causes.isEmpty()) {
            edgeContent.addSet(causes);
        }
        appendEdge(this.selectedNode, edgeContent, attackSource);
    }

    /**
     * Attacks the given attacked node with vulnerabilities from the given attacker nodes, not taking over the node.
     *
     * @param attackerNodeInGraph
     * @param attackedNodeInGraph
     * @param vulnerabilities
     */
    public void attackNodeWithVulnerabilities(AttackNodeContent attackerNodeInGraph,
            AttackNodeContent attackedNodeInGraph, Set<Vulnerability> vulnerabilities) {
        attackedNodeInGraph.attack(attackerNodeInGraph);
        final var edgeNow = getEdge(attackedNodeInGraph, attackerNodeInGraph);
        final var content = edgeNow != null ? edgeNow : new AttackStatusEdgeContent();
        final Set<VulnerabilitySurface> surfaceSet = vulnerabilities.stream().map(VulnerabilitySurface::new)
                .collect(Collectors.toSet());
        for (final var vulnerability : vulnerabilities) {
            final var vulnSurface = new VulnerabilitySurface(vulnerability);
            surfaceSet.add(vulnSurface);
            final var credentialsObtained = this.credentialsObtainedByAttack.containsKey(vulnSurface) ?
                    this.credentialsObtainedByAttack.get(vulnSurface) : new HashSet<CredentialSurface>();
            credentialsObtained.addAll(vulnerability.getGainedAttributes()
                    .stream()
                    .map(CredentialSurface::new)
                    .collect(Collectors.toSet()));
            this.credentialsObtainedByAttack.put(vulnSurface, credentialsObtained);
        }
        content.addSetV(surfaceSet.stream().collect(Collectors.toSet()));
        final var edge = appendEdge(attackedNodeInGraph, content, attackerNodeInGraph);
        this.attackEdgesToCredentialGainingVulnerabilitiesMap.put(edge, surfaceSet);
    }

    /**
     * Finds the given node inside the graph. <br/>
     * This method is necessary because nodes are created on the fly and it is crucial that
     * the actual nodes in the graph are edited (e.g. attacked or compromised), so it is necessary
     * that the actual nodes are found by this method inside the graph.
     *
     * @param nodeToFind - a {@link AttackNodeContent} containing the entity
     *                   to be found in the graph
     * @return the found node containing the entity contained in the parameter
     */
    public AttackNodeContent findNode(final AttackNodeContent nodeToFind) {
        return getGraph().nodes().stream().filter(n -> n.equals(nodeToFind)).findAny().orElse(null);
    }

    /**
     * Finds the node in the graph or otherwise adds it with an empty edge
     * (containing no attack causes yet).
     *
     * @param parent     - the parent node (must already be findable inside the
     *                   graph)
     * @param nodeToFind - the node to be found or added
     * @return the found or added node
     *
     * @see #findNode(AttackNodeContent)
     */
    public AttackNodeContent addOrFindChild(final AttackNodeContent parent,
            final AttackNodeContent nodeToFind) {
        final var foundParent = findNode(parent);
        if (foundParent != null) {
            final var found = getChildrenOfNode(foundParent).stream().filter(n -> n.equals(nodeToFind)).findAny()
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
        getGraph().nodes().forEach(n -> n.setVisited(false));
    }

    /**
     * Gets all compromisation cause IDs of the given node.
     *
     * @param node - the given node
     * @return all compromisation causes of the given node
     */
    public Set<Identifier> getCompromisationCauseIds(final AttackNodeContent node) {
        return getGraph().edges().stream().filter(e -> e.source().equals(node)).map(getGraph()::edgeValue)
                .map(e -> e.orElse(null)).filter(Objects::nonNull).map(AttackStatusEdgeContent::getCauses)
                .flatMap(Set::stream).collect(Collectors.toSet());
    }



    /**
     * Gets the {@link AttackStatusEdgeContent} between the attacked node and the
     * attacker node if it already exists, {@code null} otherwise
     *
     * @param start - the source node in the attack graph, i.e. the attacked node
     * @param end   - the targe node in the attack graph, i.e. the attacker node
     * @return the {@link AttackStatusEdgeContent} between the attacked node and the
     *         attacker node if it already exists, {@code null} otherwise
     */
    public AttackStatusEdgeContent getEdge(final AttackNodeContent start, final AttackNodeContent end) {
        final var opt = getGraph().edges().stream().filter(e -> e.source().equals(start))
                .filter(e -> e.target().equals(end)).map(getGraph()::edgeValue).findFirst().orElse(null);
        return opt != null ? opt.orElse(null) : null;
    }

    /**
     *
     * @param edgeEnds - the edge ends
     * @return the {@link AttackStatusEdgeContent} between the attacked node and the
     *         attacker node if it already exists, {@code null} otherwise
     * @see #getEdge(AttackNodeContent, AttackNodeContent)
     */
    public AttackStatusEdgeContent getEdge(final EndpointPair<AttackNodeContent> edgeEnds) {
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
    public Set<AttackNodeContent> getNodes() {
        return getGraph().nodes();
    }

    /**
     *
     * @return all the edges in the graph
     */
    public Set<AttackStatusEdge> getEdges() {
        final var ret = new HashSet<AttackStatusEdge>();
        final var edgeEndpointSet = getGraph().edges();
        for (final var edgeEnds : edgeEndpointSet) {
            ret.add(new AttackStatusEdge(getEdge(edgeEnds), edgeEnds));
        }
        return ret;
    }

    public MutableValueGraph<String, String> getStringGraph(boolean createCauselessEdges) {
        final MutableValueGraph<String, String> stringGraph = ValueGraphBuilder.directed().allowsSelfLoops(true).build();
        final var edges = getEdges();
        for (final var edge : edges) {
            if (createCauselessEdges || !edge.getContent().getCauses().isEmpty()) {
                final var endpoints = EndpointPair.ordered(edge.getNodes().source().toString(),
                    edge.getNodes().target().toString());
                stringGraph.putEdgeValue(endpoints, edge.getContent().toString());
            }
        }
        final var nodesAlreadyContained = stringGraph.nodes();
        final var nodesToBeAdded = getNodes()
                .stream()
                .filter(n -> !nodesAlreadyContained.contains(n.toString()))
                .collect(Collectors.toSet());
        nodesToBeAdded.forEach(n -> stringGraph.addNode(n.toString()));
        return stringGraph;
    }

    public Map<AttackStatusEdge, Set<CredentialSurface>> getAllCredentials() {
        final Map<AttackStatusEdge, Set<CredentialSurface>> ret =  new HashMap<>();

        for (final var edge : this.attackEdgesToCredentialGainingVulnerabilitiesMap.keySet()) {
            final Set<CredentialSurface> set = new HashSet<>();
            final var vulnSet = this.attackEdgesToCredentialGainingVulnerabilitiesMap.get(edge);
            for (final var vuln : vulnSet) {
                set.addAll(this.credentialsObtainedByAttack.get(vuln));
            }
            ret.put(edge, set);
        }

        return ret;
    }

    /**
     * Use method in tests only to change the root element before running the analysis.
     *
     * @param newCriticalEntity - the new critical entity
     */
    public void setRootForTests(Entity newCriticalEntity) {
        initializeGraph(newCriticalEntity);
    }

    @Override
    public List<AttackPathSurface> findAllAttackPaths(final BlackboardWrapper board,
            ImmutableNetwork<ArchitectureNode, AttackEdge> graph, Entity targetedElement) {
        return this.finder.findAllAttackPaths(board, graph, targetedElement);
    }
}
