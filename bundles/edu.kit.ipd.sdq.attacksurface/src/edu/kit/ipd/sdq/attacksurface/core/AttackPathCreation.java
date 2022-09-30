package edu.kit.ipd.sdq.attacksurface.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.graph.ImmutableNetwork;

import edu.kit.ipd.sdq.attacksurface.graph.ArchitectureNode;
import edu.kit.ipd.sdq.attacksurface.graph.AttackEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.DefaultAttackPathFinder;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackPath;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class AttackPathCreation {

    private Entity target;
    private CredentialChange change;

    public AttackPathCreation(Entity target, CredentialChange change) {
        this.target = target;
        this.change = change;
    }

    public void createAttackPaths(final BlackboardWrapper modelStorage,
            ImmutableNetwork<ArchitectureNode, AttackEdge> graph) {
        final var allAttackPathsSurface = new DefaultAttackPathFinder().findAttackPaths(modelStorage, graph,
                this.target);
        this.change.getAttackpaths().addAll(toAttackPaths(modelStorage, allAttackPathsSurface));
    }

    private Collection<AttackPath> toAttackPaths(final BlackboardWrapper modelStorage,
            final List<AttackPathSurface> allAttackPathsSurface) {
        final List<AttackPath> allPaths = new ArrayList<>();

        for (final var pathSurface : allAttackPathsSurface) {
            final var attackPathPath = pathSurface.toAttackPath(modelStorage, this.target, false);
            if (!attackPathPath.getAttackpathelement().isEmpty()) {
                allPaths.add(attackPathPath);
            }
        }

        return allPaths;
    }

}
