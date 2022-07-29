package edu.kit.ipd.sdq.attacksurface.graph.algorithms;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.jgrapht.Graph;
import org.jgrapht.Graphs;
import org.jgrapht.alg.shortestpath.BFSShortestPath;
import org.jgrapht.alg.shortestpath.TreeSingleSourcePathsImpl;
import org.jgrapht.alg.util.Pair;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.MethodSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.core.AttackHandlingHelper;
import edu.kit.ipd.sdq.attacksurface.graph.ArchitectureNode;
import edu.kit.ipd.sdq.attacksurface.graph.AttackEdge;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

@Deprecated
public class CredentialFilterBFS extends BFSShortestPath<ArchitectureNode, AttackEdge> {

    private List<UsageSpecification> initialBlockedCredentials;
    private BlackboardWrapper modelStorage;

    public CredentialFilterBFS(Graph<ArchitectureNode, AttackEdge> graph,
            BlackboardWrapper modelStorage) {
        super(graph);
        this.modelStorage = modelStorage;
        this.initialBlockedCredentials = AttackHandlingHelper.filteredCredentials(modelStorage);
    }

    @Override
    public SingleSourcePaths<ArchitectureNode, AttackEdge> getPaths(ArchitectureNode source) {
        if (!this.graph.containsVertex(source)) {
            throw new IllegalArgumentException(GRAPH_MUST_CONTAIN_THE_SOURCE_VERTEX);
        }

        /*
         * Initialize distanceAndPredecessorMap
         */
        Map<ArchitectureNode, Pair<Double, AttackEdge>> distanceAndPredecessorMap = new HashMap<>();
        distanceAndPredecessorMap.put(source, Pair.of(0d, null));

        /*
         * Declaring queue
         */
        Deque<ArchitectureNode> queue = new ArrayDeque<>();
        queue.add(source);

        Set<UsageSpecification> gainedCredentials = new HashSet<>(attributeProvider(source.getEntity()).toList());
        /*
         * Take the top most vertex from the queue, relax its outgoing edges, update the distance of
         * the neighbouring vertices and push them into the queue
         */
        while (!queue.isEmpty()) {
            var v = queue.poll();
            for (AttackEdge e : this.graph.outgoingEdgesOf(v)) {
//                if (credentialCheck(e, gainedCredentials)) {
//                    continue;
//                }
//                if (e.getCause() != null) {
//                    gainedCredentials.addAll(e.getCause().getGainedAttributes());
//                }
                var u = Graphs.getOppositeVertex(this.graph, e, v);
                if (!distanceAndPredecessorMap.containsKey(u)) {
                    queue.add(u);
                    gainedCredentials.addAll(attributeProvider(u.getEntity()).toList());
                    var newDist = 0D;
                    if (e.getCause() == null) {
                        newDist = distanceAndPredecessorMap.get(v).getFirst() + 10000.0;
                    } else {
                        newDist = distanceAndPredecessorMap.get(v).getFirst() + 1.0;
                    }
                    distanceAndPredecessorMap.put(u, Pair.of(newDist, e));
                }
            }
        }

        return new TreeSingleSourcePathsImpl<>(this.graph, source, distanceAndPredecessorMap);

    }

    private boolean credentialCheck(AttackEdge edge, Set<UsageSpecification> credentials) {
        if (edge.getCredentials() == null || edge.getCredentials().isEmpty()) {
            return false;
        }
        var blocked = edge.getCredentials().stream()
                .filter(e -> this.initialBlockedCredentials.stream()
                        .anyMatch(cred -> EcoreUtil.equals(cred.getAttribute(), e.getAttribute())
                                && EcoreUtil.equals(e.getAttributevalue(), cred.getAttributevalue())))
                .toList();
        return !blocked.stream().allMatch(
                e -> credentials.stream().anyMatch(cred -> EcoreUtil.equals(cred.getAttribute(), e.getAttribute())
                        && EcoreUtil.equals(e.getAttributevalue(), cred.getAttributevalue())));
    }

    private Stream<UsageSpecification> attributeProvider(Entity entity) {
        return this.modelStorage.getSpecification().getAttributeprovider().stream()
                .filter(PCMAttributeProvider.class::isInstance).map(PCMAttributeProvider.class::cast).filter(e -> {
                    if (entity instanceof AssemblyContext) {
                        return EcoreUtil.equals(e.getAssemblycontext(), entity);
                    }
                    if (entity instanceof LinkingResource) {
                        return EcoreUtil.equals(e.getLinkingresource(), entity);
                    }
                    if (entity instanceof ResourceContainer) {
                        return EcoreUtil.equals(e.getResourcecontainer(), entity);
                    }
                    if (entity instanceof MethodSpecification) {
                        return EcoreUtil.equals(e.getMethodspecification(), entity);
                    }
                    return false;
                }).map(PCMAttributeProvider::getAttribute);
    }

}
