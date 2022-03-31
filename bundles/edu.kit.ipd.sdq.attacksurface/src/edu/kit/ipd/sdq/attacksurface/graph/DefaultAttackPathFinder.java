package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.Map;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import com.google.common.graph.EndpointPair;

import edu.kit.ipd.sdq.attacksurface.core.AttackHandlingHelper;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

class DefaultAttackPathFinder implements AttackPathFinder {
    private final AttackGraph graph;
    private final Set<AttackStatusNodeContent> startOfAttacks;

    DefaultAttackPathFinder(final AttackGraph graph) {
        this.graph = graph;
        this.startOfAttacks = new HashSet<>();
    }

    @Override
    public List<AttackPathSurface> findAllAttackPaths(final BlackboardWrapper board, final CredentialChange changes) {
        this.graph.resetVisitations();
        List<AttackPathSurface> allPaths = new ArrayList<>();
        this.startOfAttacks.clear();

        final var nodeIterable = getNodeIterable();
        boolean isChanged = false;
        for (final var nodeContentToFind : nodeIterable) {
            final var node = this.graph.findNode(nodeContentToFind);
            if (!node.isVisited()) {
                isChanged |= calculatePathsForNode(board, changes, nodeContentToFind, allPaths);
            }
        }
        if (isChanged) {
            // re-run the attack-path generation if attack with initially required
            // credentials requires this
            allPaths = findAllAttackPaths(board, changes);
        }
        return filterResult(board, allPaths);
    }

    private Iterable<AttackStatusNodeContent> getNodeIterable() {
        return () -> new Iterator<>() {
            private AttackStatusNodeContent node = graph.getRootNodeContent();
            private final List<AttackStatusNodeContent> children = new ArrayList<>();
            private final Set<AttackStatusNodeContent> childrenSet = new HashSet<>();
            private final Map<AttackStatusNodeContent, Boolean> addedChildren = new HashMap<>();
            
            @Override
            public boolean hasNext() {
                return this.node != null;
            }

            @Override
            public AttackStatusNodeContent next() {
                final var ret = this.node;
                
                this.addedChildren.computeIfAbsent(this.node, n -> false);
                if (!this.addedChildren.get(this.node).booleanValue()) {
                    final var childrenOfNode = sortedByAttackEdgeRelevancy(graph.getChildrenOfNode(this.node));
                    childrenOfNode.forEach(c -> {
                        if (!this.childrenSet.contains(c)) {
                            this.children.add(c);
                            this.childrenSet.add(c);
                        }
                    });
                    this.addedChildren.put(this.node, true);
                }
                if (this.children.isEmpty()) {
                    this.node = null;
                } else {
                    this.node = this.children.remove(0);
                }
                
                if (ret == null) {
                    throw new NoSuchElementException("no element available");
                }
                return ret;
            }

            private List<AttackStatusNodeContent> sortedByAttackEdgeRelevancy(
                    Set<AttackStatusNodeContent> childrenOfNode) {
                return sortedByRelevancy(this.node, childrenOfNode);
            }
        };
    }
    

    private List<AttackStatusNodeContent> getChildrenOfNode(AttackStatusNodeContent node) {
        final var childrenSet = this.graph.getChildrenOfNode(node);
        return sortedByRelevancy(node, childrenSet);
    }
    
    private List<AttackStatusNodeContent> sortedByRelevancy(
            final AttackStatusNodeContent attackedNode,
            final Collection<AttackStatusNodeContent> collection) {
        final var ret = new ArrayList<>(collection);
        Collections.sort(ret, getContentComparator(attackedNode));
        return ret;
    }
    
    private Comparator<AttackStatusNodeContent> getContentComparator(final AttackStatusNodeContent attackedNode) {
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
                    final var edgeA = graph.getEdge(attackedNode, a);
                    final int causeSizeA = edgeA.getCCollectionSize() + edgeA.getVCollectionSize();
                    final var edgeB = graph.getEdge(attackedNode, b);
                    final int causeSizeB = edgeB.getCCollectionSize() + edgeB.getVCollectionSize();
                 
                    return Integer.compare(causeSizeB, causeSizeA); 
                }
                return a.getTypeOfContainedElement().compareTo(b.getTypeOfContainedElement());
            } else if (isAttackedByA) {
                return -1; 
            }
            return 1; // isAttackedByB
        };
    }

    private boolean calculatePathsForNode(final BlackboardWrapper board, final CredentialChange changes,
            final AttackStatusNodeContent nodeContentToFind, final List<AttackPathSurface> allPaths) {
        final var node = this.graph.findNode(nodeContentToFind);
        final boolean isNodeAttacked = node.isAttacked();
        final boolean isChanged = attackNodeContentWithInitialCredentialIfNecessary(board, node, changes);
        if (isNodeAttacked) {
            final List<AttackStatusNodeContent> children = getChildrenOfNode(node);
            for (final var child : children) {
                final boolean isAttackedByChild = node.isAttackedBy(child);
                
                if (isAttackedByChild || !startOfAttacks.contains(node)) {
                    final var edgeValue = this.graph.getEdge(node, child);
                    final var edge = new AttackStatusEdge(edgeValue, EndpointPair.ordered(node, child));
                    addEdge(allPaths, edge, isAttackedByChild);
                    node.setVisited(true);
                }

                final boolean isStartOfAttack = !node.isAttackedBy(child);
                if (isStartOfAttack) {
                    this.startOfAttacks.add(child);
                }
            }
        }
        return isChanged;
    }

    // remove duplicate paths, partial paths and invalid paths
    private List<AttackPathSurface> filterResult(final BlackboardWrapper board, final List<AttackPathSurface> paths) {
        return paths.stream().distinct().filter(p -> !p.isEmpty())
                .filter(p -> p.get(p.size() - 1).getNodes().target().equals(this.graph.getRootNodeContent()))
                .map(AttackPathSurface::fillCredentialsInitiallyNecessary)
                .filter(p -> p.isValid(board, this.graph.getRootNodeContent().getContainedElement()))
                .filter(AttackPathSurface::containsInitiallyNecessaryCredentials).collect(Collectors.toList());
    }

    private boolean attackNodeContentWithInitialCredentialIfNecessary(final BlackboardWrapper board,
            final AttackStatusNodeContent node, final CredentialChange changes) {
        final boolean isCompromised = AttackHandlingHelper.attackNodeContentWithInitialCredentialIfNecessary(board,
                this.graph, node);
        if (isCompromised && node.getTypeOfContainedElement().equals(PCMElementType.RESOURCE_CONTAINER)) {
            final var dataHandler = new DataHandlerAttacker(changes);
            final var attackInnerHandler = new AssemblyContextContext(board, dataHandler, this.graph);
            attackInnerHandler.attackAssemblyContext(getContainedComponents(node), changes, node.getContainedElement(),
                    true);
        }
        return isCompromised;
    }

    private List<AssemblyContext> getContainedComponents(AttackStatusNodeContent containerNode) {
        return this.graph.getParentsOfNode(containerNode).stream()
                .filter(n -> n.getTypeOfContainedElement().equals(PCMElementType.ASSEMBLY_CONTEXT))
                .map(n -> n.getContainedElementAsPCMElement().getAssemblycontext()).collect(Collectors.toList());
    }

    private void addEdge(final List<AttackPathSurface> allPaths, final AttackStatusEdge edge,
            final boolean isAttackEdge) {
        final var reverseEdge = edge.createReverseEdge();
        final var edgePath = reverseEdge.toPath();
        if (allPaths.isEmpty() && isAttackEdge) {
            allPaths.add(edgePath);
        } else {
            final List<AttackPathSurface> newPaths = new ArrayList<>();
            final boolean isEdgeSimplePath = reverseEdge.getNodes().target().equals(this.graph.getRootNodeContent());
            if (isEdgeSimplePath && isAttackEdge) {
                newPaths.add(edgePath);
            }
            allPaths.forEach(p -> {
                final var pathCopy = p.getCopy();
                final boolean doAddCopy = addEdgeIfFitting(p, reverseEdge);
                if (doAddCopy) {
                    newPaths.add(pathCopy);
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
}
