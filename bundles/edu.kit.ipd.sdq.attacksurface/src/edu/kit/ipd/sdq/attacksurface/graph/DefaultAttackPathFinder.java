package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.jgrapht.alg.shortestpath.BFSShortestPath;
import org.jgrapht.graph.guava.ImmutableNetworkAdapter;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.MaximumPathLengthFilterCriterion;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.graph.EndpointPair;
import com.google.common.graph.ImmutableNetwork;

import edu.kit.ipd.sdq.attacksurface.core.AttackHandlingHelper;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * The default implementation of {@link AttackPathFinder}.
 *
 * @author ugnwq
 * @version 0.9
 */
public class DefaultAttackPathFinder implements AttackPathFinder {
    private final AttackGraph graph;
    private final Set<AttackNodeContent> startOfAttacks;
    private int sizeMaximum;

    public DefaultAttackPathFinder(final AttackGraph graph) {
        this.graph = graph;
        this.startOfAttacks = new HashSet<>();
    }

    private void setSizeMaximum(final BlackboardWrapper board) {
        this.sizeMaximum = AttackHandlingHelper.getSurfaceAttacker(board).getFiltercriteria()
                .stream()
                .filter(MaximumPathLengthFilterCriterion.class::isInstance)
                .map(MaximumPathLengthFilterCriterion.class::cast)
                .filter(m -> m.getMaximumPathLength() >= 0)
                .mapToInt(MaximumPathLengthFilterCriterion::getMaximumPathLength)
                .min().orElse(Integer.MAX_VALUE);
    }

    @Override
    public List<AttackPathSurface> findAllAttackPaths(final BlackboardWrapper board,
            ImmutableNetwork<ArchitectureNode, AttackEdge> graph, Entity targetedElement) {
        setSizeMaximum(board);

//        this.graph.resetVisitations();
        List<AttackPathSurface> allPaths = new ArrayList<>();
        this.startOfAttacks.clear();

        var rootNode = new ArchitectureNode(targetedElement);
        var targedNote = new ArchitectureNode(targetedElement);

        var test = new ImmutableNetworkAdapter<>(graph);

        var path = BFSShortestPath.findPathBetween(test, rootNode, targedNote);

        path.getEdgeList();



        final var nodeIterable = getNodeIterable();
        for (final var nodeContentToFind : nodeIterable) {
            final var node = this.graph.findNode(nodeContentToFind);
            if (!node.isVisited()) {
//                calculatePathsForNode(board, changes, nodeContentToFind, allPaths);
            }
        }
        return filterResult(board, allPaths);
    }

    private Iterable<AttackNodeContent> getNodeIterable() {
        return NodeIterator::new;
    }


    private List<AttackNodeContent> getChildrenOfNode(AttackNodeContent node) {
        final var childrenSet = this.graph.getChildrenOfNode(node);
        return sortedByRelevancy(node, childrenSet);
    }

    private List<AttackNodeContent> sortedByRelevancy(
            final AttackNodeContent attackedNode,
            final Collection<AttackNodeContent> collection) {
        final var ret = new ArrayList<>(collection);
        Collections.sort(ret, getContentComparator(attackedNode));
        return ret;
    }

    private Comparator<AttackNodeContent> getContentComparator(final AttackNodeContent attackedNode) {
        Objects.requireNonNull(attackedNode);
        return (a,b) -> { // sorts so that more relevant nodes are first (smaller)
            if (a.equals(b)) {
                return 0;
            } else if (a.equals(attackedNode)) {
                return Integer.MIN_VALUE;
            } else if (b.equals(attackedNode)) {
                return Integer.MAX_VALUE;
            }

            final var isAttackedByA = attackedNode.isAttackedBy(a);
            final var isAttackedByB = attackedNode.isAttackedBy(b);
            if (isAttackedByA == isAttackedByB) {
                if (isAttackedByA) {
                    final var edgeA = this.graph.getEdge(attackedNode, a);
                    final var causeSizeA = edgeA.getCCollectionSize() + edgeA.getVCollectionSize();
                    final var edgeB = this.graph.getEdge(attackedNode, b);
                    final var causeSizeB = edgeB.getCCollectionSize() + edgeB.getVCollectionSize();

                    return Integer.compare(causeSizeB, causeSizeA);
                }
                return a.getTypeOfContainedElement().compareTo(b.getTypeOfContainedElement());
            } else if (isAttackedByA) {
                return -1;
            }
            return 1; // isAttackedByB
        };
    }

    private void calculatePathsForNode(final BlackboardWrapper board, final CredentialChange changes,
            final AttackNodeContent nodeContentToFind,
            final List<AttackPathSurface> allPaths) {
        final var node = this.graph.findNode(nodeContentToFind);
        final var isNodeAttacked = node.isAttacked();

        if (isNodeAttacked) {
            final var children = getChildrenOfNode(node);
            for (final var child : children) {
                final var isAttackedByChild = node.isAttackedBy(child);

                if (isAttackedByChild || !this.startOfAttacks.contains(node)) {
                    final var edgeValue = this.graph.getEdge(node, child);
                    final var edge = new AttackStatusEdge(edgeValue, EndpointPair.ordered(node, child));
                    addEdge(allPaths, edge, isAttackedByChild);
                    node.setVisited(true);
                }

                final var isStartOfAttack = !isAttackedByChild;
                if (isStartOfAttack) {
                    this.startOfAttacks.add(child);
                }
            }
        }
    }

    // remove duplicate paths, partial paths and invalid paths
    private List<AttackPathSurface> filterResult(final BlackboardWrapper board, final List<AttackPathSurface> paths) {
        return paths.stream().distinct().filter(p -> !p.isEmpty())
                .filter(p -> p.get(p.size() - 1).getNodes().target().equals(this.graph.getRootNodeContent()))
                .map(AttackPathSurface::fillCredentialsInitiallyNecessary)
                .filter(p -> p.isValid(board, this.graph.getRootNodeContent().getContainedElement()))
                .filter(AttackPathSurface::containsInitiallyNecessaryCredentials).collect(Collectors.toList());
    }

//    private boolean attackNodeContentWithInitialCredentialIfNecessary(final BlackboardWrapper board,
//            final ArchitectureNode node, final CredentialChange changes) {
//        final var isCompromised = AttackHandlingHelper.attackNodeContentWithInitialCredentialIfNecessary(board,
//                this.graph, node);
//        if (isCompromised && node.getTypeOfContainedElement().equals(PCMElementType.RESOURCE_CONTAINER)) {
//            final var dataHandler = new DataHandlerAttacker(changes);
//            final var attackInnerHandler = new AssemblyContextContext(board, dataHandler, this.graph);
//            attackInnerHandler.attackAssemblyContext(List.of(getContainedComponents(node)), changes,
//                    node.getContainedElement(),
//                    true);
//        }
//        return isCompromised;
//    }

    private List<AssemblyContext> getContainedComponents(AttackNodeContent containerNode) {
        return this.graph.getParentsOfNode(containerNode).stream()
                .filter(n -> n.getTypeOfContainedElement().equals(PCMElementType.ASSEMBLY_CONTEXT))
                .map(n -> n.getContainedElementAsPCMElement().getAssemblycontext().get(0)).collect(Collectors.toList()); // TODO
                                                                                                                         // list
    }

    private void addEdge(final List<AttackPathSurface> allPaths, final AttackStatusEdge edge,
            final boolean isAttackEdge) {
        final var reverseEdge = edge.createReverseEdge();
        final var edgePath = reverseEdge.toPath();
        if (allPaths.isEmpty() && isAttackEdge) {
            allPaths.add(edgePath);
        } else {
            final List<AttackPathSurface> newPaths = new ArrayList<>();
            final var isEdgeSimplePath = reverseEdge.getNodes().target().equals(this.graph.getRootNodeContent());
            if (isEdgeSimplePath && isAttackEdge) {
                newPaths.add(edgePath);
            }
            allPaths.stream()
                .filter(p -> isFitting(p, reverseEdge))
                .forEach(p -> {
                    if (p.size() < getSizeMaximum()) {
                        final var pathCopy = p.getCopy();
                        pathCopy.addFirst(reverseEdge);
                        newPaths.add(pathCopy);
                    }
            });
            allPaths.addAll(newPaths);
        }
    }

    private int getSizeMaximum() {
        return this.sizeMaximum;
    }

    private boolean isFitting(final AttackPathSurface path, final AttackStatusEdge edge) {
        return path.get(0).getNodes().source().equals(edge.getNodes().target());
    }

    private class NodeIterator implements Iterator<AttackNodeContent> {
        private AttackNodeContent node;
        private final List<AttackNodeContent> iterableList;
        private final Iterator<AttackNodeContent> listIterator;
        private final Set<AttackNodeContent> childrenSet;
        private final Map<AttackNodeContent, Boolean> addedChildren;

        public NodeIterator() {
            this.node = DefaultAttackPathFinder.this.graph.getRootNodeContent();
            this.iterableList = new ArrayList<>();
            this.childrenSet = new HashSet<>();
            this.addedChildren = new HashMap<>();

            addChildrenForNode(this.node);

            this.listIterator = this.iterableList.iterator();
        }

        private void addChildrenForNode(final AttackNodeContent nodeToBeConsidered) {
            this.iterableList.add(nodeToBeConsidered);

            this.addedChildren.computeIfAbsent(nodeToBeConsidered, n -> false);
            if (!this.addedChildren.get(nodeToBeConsidered).booleanValue()) {
                final var childrenOfNode = sortedByAttackEdgeRelevancy(
                        nodeToBeConsidered, DefaultAttackPathFinder.this.graph.getChildrenOfNode(nodeToBeConsidered));
                childrenOfNode.forEach(c -> {
                    if (!this.childrenSet.contains(c)) {
                        this.iterableList.add(c);
                        this.childrenSet.add(c);
                    }
                });
                this.addedChildren.put(nodeToBeConsidered, true);
                childrenOfNode.forEach(this::addChildrenForNode);
            }
        }

        @Override
        public boolean hasNext() {
            return this.listIterator.hasNext();
        }

        @Override
        public AttackNodeContent next() {
            return this.listIterator.next();
        }

        private List<AttackNodeContent> sortedByAttackEdgeRelevancy(final AttackNodeContent attackedNode,
                Set<AttackNodeContent> childrenOfNode) {
            return sortedByRelevancy(attackedNode, childrenOfNode);
        }
    }
}
