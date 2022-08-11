package edu.kit.ipd.sdq.attacksurface.graph;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jgrapht.alg.shortestpath.YenKShortestPath;
import org.jgrapht.graph.WeightedMultigraph;
import org.jgrapht.graph.guava.ImmutableNetworkAdapter;
import org.jgrapht.nio.Attribute;
import org.jgrapht.nio.AttributeType;
import org.jgrapht.nio.DefaultAttribute;
import org.jgrapht.nio.dot.DOTExporter;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.MaximumPathLengthFilterCriterion;
import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.graph.ImmutableNetwork;

import edu.kit.ipd.sdq.attacksurface.core.AttackHandlingHelper;
import edu.kit.ipd.sdq.attacksurface.graph.algorithms.CredentialValidator;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

/**
 * The default implementation of {@link AttackPathFinder}.
 *
 * @author ugnwq, majuwa
 * @version 2.0
 */
public class DefaultAttackPathFinder implements AttackPathFinder {

    private int sizeMaximum;

    private void setSizeMaximum(final BlackboardWrapper board) {
        this.sizeMaximum = AttackHandlingHelper.getSurfaceAttacker(board).getFiltercriteria().stream()
                .filter(MaximumPathLengthFilterCriterion.class::isInstance)
                .map(MaximumPathLengthFilterCriterion.class::cast).filter(m -> m.getMaximumPathLength() >= 0)
                .mapToInt(MaximumPathLengthFilterCriterion::getMaximumPathLength).min().orElse(Integer.MAX_VALUE);
    }

    @Override
    public List<AttackPathSurface> findAttackPaths(final BlackboardWrapper board,
            ImmutableNetwork<ArchitectureNode, AttackEdge> graph, Entity targetedElement) {
        setSizeMaximum(board);

        List<AttackPathSurface> allPaths = new ArrayList<>();

        var rootNode = new ArchitectureNode(targetedElement);

        var graphAdapter = new ImmutableNetworkAdapter<>(graph);
        exportGraph(graphAdapter);

        var startNodes = AttackHandlingHelper.getStartNodes(board);
        var nodes = startNodes.isEmpty() ? graphAdapter.vertexSet() : startNodes;
        calculatePaths(board, nodes, allPaths, rootNode, graphAdapter);

        return allPaths;
    }

    private void calculatePaths(final BlackboardWrapper board, Set<ArchitectureNode> nodes,
            List<AttackPathSurface> allPaths, ArchitectureNode rootNode,
            ImmutableNetworkAdapter<ArchitectureNode, AttackEdge> graphAdapter) {

        var paths = nodes.parallelStream().filter(node -> !node.equals(rootNode))
                .flatMap(node -> (new YenKShortestPath<>(graphAdapter, new CredentialValidator(board)))
                        .getPaths(node, rootNode, 1).stream())
                .filter(Objects::nonNull).map(AttackPathSurface::new).filter(path -> path.size() < this.sizeMaximum)
                .toList();

        allPaths.addAll(paths);

//        for (var node : nodes) {
//            var paths = (new YenKShortestPath<>(graphAdapter, new CredentialValidator(board))).getPaths(node, rootNode,
//                    1);
//
////            var paths = new AllDirectedPaths<>(graphAdapter, new CredentialValidator(board)).getAllPaths(node, rootNode,
////                    false, 200);
//
//            for (var path : paths) {
//
//            if (path != null && !node.equals(rootNode)) {
//                var attackPath = new AttackPathSurface(path);
//                if (attackPath.size() < this.sizeMaximum) {
//                    allPaths.add(new AttackPathSurface(path));
//                }
//            }
//        }
//        }
    }

    private void copyGraph(ImmutableNetworkAdapter<ArchitectureNode, AttackEdge> graphAdapter) {
        var sdf = new WeightedMultigraph<ArchitectureNode, AttackEdge>(AttackEdge.class);
        graphAdapter.vertexSet().stream().forEach(sdf::addVertex);
        graphAdapter.edgeSet().stream()
                .forEach(e -> sdf.addEdge(new ArchitectureNode(e.getRoot()), new ArchitectureNode(e.getTarget()), e));
    }

    private void exportGraph(ImmutableNetworkAdapter<ArchitectureNode, AttackEdge> graphAdapter) {
        var export = new DOTExporter<ArchitectureNode, AttackEdge>(ArchitectureNode::toString);
        export.setEdgeIdProvider(AttackEdge::toString);
        export.setEdgeAttributeProvider(e -> {
            Map<String, Attribute> attribs = new HashMap<>();
            attribs.put("label", new DefaultAttribute<>(e.toString(), AttributeType.STRING));
            return attribs;
        });
        export.exportGraph(graphAdapter, new File("test.dot"));
    }

}
