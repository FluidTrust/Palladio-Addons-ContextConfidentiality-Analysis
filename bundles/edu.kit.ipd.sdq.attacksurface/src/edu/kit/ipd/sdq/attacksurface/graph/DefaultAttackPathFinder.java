package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import com.google.common.graph.EndpointPair;
import com.google.common.graph.Graphs;
import com.google.common.graph.Traverser;

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
        List<AttackPathSurface> allPaths = new ArrayList<>();
        this.startOfAttacks.clear();

        Traverser<AttackStatusNodeContent> traverser = Traverser.forGraph(copy().getGraph());
        final var dfsIterable = traverser.depthFirstPreOrder(this.graph.getRootNodeContent());
        boolean isChanged  = false;
        for (final var nodeContentToFind : dfsIterable) {
            final var node = this.graph.findNode(nodeContentToFind);
            final boolean isNodeAttacked = node.isAttacked();
            isChanged |= attackNodeContentWithInitialCredentialIfNecessary(board, node, changes);
            if (isNodeAttacked) {
                final List<AttackStatusNodeContent> children = getChildrenOfNode(node);
                for (final var child : children) {
                    final boolean isAttackedByChild = node.isAttackedBy(child);
                    if (isAttackedByChild || !startOfAttacks.contains(node)) {
                        final var edgeValue = this.graph.getEdge(node, child);
                        final var edge = new AttackStatusEdge(edgeValue, EndpointPair.ordered(node, child));
                        addEdge(allPaths, edge, isAttackedByChild);
                    }
                    
                    final boolean isStartOfAttack = !node.isAttackedBy(child);
                    if (isStartOfAttack) {
                        this.startOfAttacks.add(child);
                    }
                }
            }
        }
        if (isChanged) {
            allPaths = findAllAttackPaths(board, changes);
        }
        return filterResult(board, allPaths);
    }
    
    private List<AttackStatusNodeContent> getChildrenOfNode(AttackStatusNodeContent node) {
        final List<AttackStatusNodeContent> children = new ArrayList<>();
        final var childrenSet = this.graph.getChildrenOfNode(node);
        children.addAll(childrenSet);
        if (childrenSet.contains(node)) {
            for (int i = 0; i < children.size(); i++) {
                if (children.get(i).equals(node)) {
                    final var tmp = children.set(0, node);
                    children.set(i, tmp);
                }
            }
        }
        return children;
    }

    // remove duplicate paths, partial paths and invalid paths
    private List<AttackPathSurface> filterResult(final BlackboardWrapper board, 
            final List<AttackPathSurface> paths) {
        return paths.stream()
                .distinct()
                .filter(p -> !p.isEmpty())
                .filter(p -> p.get(p.size() - 1).getNodes().target().equals(this.graph.getRootNodeContent()))
                .map(AttackPathSurface::fillCredentialsInitiallyNecessary)
                .filter(p -> p.isValid(board, this.graph.getRootNodeContent().getContainedElement()))
                .filter(AttackPathSurface::containsInitiallyNecessaryCredentials)
                .collect(Collectors.toList());
    }

    private AttackGraph copy() {
        final var copyGraph = Graphs.copyOf(this.graph.getGraph());
        return new AttackGraph(this.graph.getRootNodeContent(), copyGraph);
    }

    private boolean attackNodeContentWithInitialCredentialIfNecessary(final BlackboardWrapper board,
            final AttackStatusNodeContent node, final CredentialChange changes) {
        final boolean isCompromised = AttackHandlingHelper
                .attackNodeContentWithInitialCredentialIfNecessary(board, this.graph, node);
        if (isCompromised && node.getTypeOfContainedElement().equals(PCMElementType.RESOURCE_CONTAINER)) {
            final var dataHandler = new DataHandlerAttacker(changes);
            final var attackInnerHandler = new AssemblyContextContext(board, dataHandler, this.graph);
            attackInnerHandler.attackAssemblyContext(getContainedComponents(node), changes, 
                    node.getContainedElement(),
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
            final boolean isEdgeSimplePath = reverseEdge.getNodes().target()
                    .equals(this.graph.getRootNodeContent());
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
