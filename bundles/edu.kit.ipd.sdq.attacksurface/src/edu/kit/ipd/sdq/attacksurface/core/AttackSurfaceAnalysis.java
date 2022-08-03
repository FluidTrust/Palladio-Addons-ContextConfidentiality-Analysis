package edu.kit.ipd.sdq.attacksurface.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.graph.ImmutableNetwork;

import edu.kit.ipd.sdq.attacksurface.graph.ArchitectureNode;
import edu.kit.ipd.sdq.attacksurface.graph.AttackEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraphCreation;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.DefaultAttackPathFinder;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.api.IAttackPropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackPath;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

/**
 * Entry point for attack surface propagation
 *
 * @author majuwa
 * @author ugnwq
 * @version 2.0
 */
//@Component(service = IAttackPropagationAnalysis.class)
public class AttackSurfaceAnalysis implements IAttackPropagationAnalysis {

    private CredentialChange changes;

    private Entity crtitcalEntity;

    /**
     * Runs the analysis.
     *
     * @param modelStorage
     *            - the model storage
     */
    @Override
    public void runChangePropagationAnalysis(final BlackboardWrapper modelStorage) {
        this.changes = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();


        createInitialStructure(modelStorage);
        var graph = new AttackGraphCreation(modelStorage);

        graph.calculateAssemblyContextToAssemblyContextPropagation();
        graph.calculateAssemblyContextToGlobalAssemblyContextPropagation();
        graph.calculateAssemblyContextToLinkingResourcePropagation();
        graph.calculateAssemblyContextToLocalResourcePropagation();
        graph.calculateAssemblyContextToRemoteResourcePropagation();

        graph.calculateLinkingResourceToAssemblyContextPropagation();
        graph.calculateLinkingResourceToResourcePropagation();

        graph.calculateResourceContainerToLinkingResourcePropagation();
        graph.calculateResourceContainerToLocalAssemblyContextPropagation();
        graph.calculateResourceContainerToRemoteAssemblyContextPropagation();
        graph.calculateResourceContainerToResourcePropagation();




        createAttackPaths(modelStorage, graph.getGraph());

    }


    private void createAttackPaths(final BlackboardWrapper modelStorage,
            ImmutableNetwork<ArchitectureNode, AttackEdge> graph) {
        final var allAttackPathsSurface = new DefaultAttackPathFinder().findAttackPaths(modelStorage,
                graph, this.crtitcalEntity);
        this.changes.getAttackpaths().addAll(toAttackPaths(modelStorage, allAttackPathsSurface));
    }

    /**
     * Method for testing the {@link AttackPathSurface} to {@link AttackPath} conversion.
     *
     * @param allAttackPathsSurface
     *            - list of {@link AttackPathSurface} instances representing all found paths
     * @param modelStorage
     * @return list of {@link AttackPath} instances
     */
    public List<AttackPath> toAttackPaths(final List<AttackPathSurface> allAttackPathsSurface,
            final BlackboardWrapper modelStorage) {
        return new ArrayList<>(toAttackPaths(modelStorage, allAttackPathsSurface));
    }

    private Collection<AttackPath> toAttackPaths(final BlackboardWrapper modelStorage,
            final List<AttackPathSurface> allAttackPathsSurface) {
        final List<AttackPath> allPaths = new ArrayList<>();

        for (final var pathSurface : allAttackPathsSurface) {
            final var attackPathPath = pathSurface.toAttackPath(modelStorage, this.crtitcalEntity, false);
            if (!attackPathPath.getAttackpathelement().isEmpty()) {
                allPaths.add(attackPathPath);
            }
        }

        return allPaths;
    }

    private void createInitialStructure(BlackboardWrapper board) {
        final var repository = board.getModificationMarkRepository();
        final var localAttacker = AttackHandlingHelper.getSurfaceAttacker(board);

        repository.getChangePropagationSteps().clear();

        final var criticalPCMElement = localAttacker.getTargetedElement();
        this.crtitcalEntity = PCMElementType.typeOf(criticalPCMElement).getEntity(criticalPCMElement);

        board.getModificationMarkRepository().getChangePropagationSteps().add(this.changes);
//        this.attackGraph = this.attackGraph != null ? this.attackGraph : new AttackGraph(this.crtitcalEntity);
//
//        final var setCredentials = localAttacker.getAttacker().getCredentials().stream().map(CredentialSurface::new)
//                .collect(Collectors.toSet());
//        this.attackGraph.addCredentialsFromBeginningOn(setCredentials);
//        convertAffectedElementsToChanges(localAttacker);
//        addAllPossibleAttacks(board, localAttacker);
//        board.getModificationMarkRepository().getChangePropagationSteps().add(this.changes);
    }










}
