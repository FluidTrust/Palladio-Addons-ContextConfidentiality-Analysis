package edu.kit.ipd.sdq.attacksurface.core;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.SurfaceAttacker;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;

public final class FilterCriteriaHandling {
    private FilterCriteriaHandling() {
        assert false;
    }
    
    public static boolean isFiltered(final BlackboardWrapper board, final AttackGraph attackGraph,
            final AttackPath path) {
        final var surfaceAttacker = getSurfaceAttacker(board);
        final var filterCriteria = surfaceAttacker.getFiltercriteria();
        final var systemIntegration = path.getPath().get(path.getPath().size() - 1);
        for (final var filterCriterion : filterCriteria) {
            if (filterCriterion.isFilteringEarly() 
                    && filterCriterion.isElementFiltered(systemIntegration, surfaceAttacker, path)) {
                return true;
            }
        }
        return false;
    }
    
    private static SurfaceAttacker getSurfaceAttacker(final BlackboardWrapper board) {
        if (board.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().isEmpty()) {
            throw new IllegalStateException("No attacker selected");
        }
        if (board.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().size() > 2) {
            throw new IllegalStateException("More than one attacker");
        }
        return board.getModificationMarkRepository().getSeedModifications().getSurfaceattackcomponent().get(0)
                .getAffectedElement();
    }
}
