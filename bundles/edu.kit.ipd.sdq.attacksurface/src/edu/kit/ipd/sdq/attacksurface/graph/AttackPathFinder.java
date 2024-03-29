package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.List;

import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.graph.ImmutableNetwork;

import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

/**
 * An interface for finding all attack paths.
 *
 * @author ugnwq
 * @version 1.0
 */
public interface AttackPathFinder {

    /**
     * Finds all possible attack paths in the graph. <br />
     * Additionally, paths with initially necessary credentials.
     *
     * @param modelStorage
     *            - the model storage
     * @param changes
     *            - the changes
     * @return all possible attack paths
     */
    List<AttackPathSurface> findAttackPaths(BlackboardWrapper board,
            ImmutableNetwork<ArchitectureNode, AttackEdge> graph, Entity targetedElement);
}
