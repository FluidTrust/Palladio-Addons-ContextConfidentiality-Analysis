package edu.kit.ipd.sdq.attacksurface.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
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

    private static final Logger LOGGER = Logger.getLogger(AttackSurfaceAnalysis.class.getName());

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
        VulnerabilityHelper.initializeVulnerabilityStorage(modelStorage.getVulnerabilitySpecification());

        createInitialStructure(modelStorage);
        var graph = new AttackGraphCreation(modelStorage);

        // calculate the attack graph in parallel
        var future = CompletableFuture
                .allOf(
                CompletableFuture.runAsync(graph::calculateAssemblyContextToAssemblyContextPropagation),

                CompletableFuture.runAsync(graph::calculateAssemblyContextToAssemblyContextPropagation),
                CompletableFuture.runAsync(graph::calculateAssemblyContextToGlobalAssemblyContextPropagation),
                CompletableFuture.runAsync(graph::calculateAssemblyContextToLinkingResourcePropagation),
                CompletableFuture.runAsync(graph::calculateAssemblyContextToLocalResourcePropagation),
                CompletableFuture.runAsync(graph::calculateAssemblyContextToRemoteResourcePropagation),

                CompletableFuture.runAsync(graph::calculateLinkingResourceToAssemblyContextPropagation),
                CompletableFuture.runAsync(graph::calculateLinkingResourceToResourcePropagation),

                CompletableFuture.runAsync(graph::calculateResourceContainerToLinkingResourcePropagation),
                CompletableFuture.runAsync(graph::calculateResourceContainerToLocalAssemblyContextPropagation),
                CompletableFuture.runAsync(graph::calculateResourceContainerToRemoteAssemblyContextPropagation),
                CompletableFuture.runAsync(graph::calculateResourceContainerToResourcePropagation));
        try {
            future.get();
        } catch (ExecutionException e) {
            LOGGER.log(Level.SEVERE, "Error during graph creation", e);
            Thread.currentThread().interrupt();
            throw new IllegalStateException("IllegalState durin graph creation", e);
        } catch (InterruptedException e) {
            LOGGER.log(Level.SEVERE, "Error during graph creation", e);
            Thread.currentThread().interrupt();
        }



        createAttackPaths(modelStorage, graph.getGraph());
        VulnerabilityHelper.resetMap();

    }


    private void createAttackPaths(final BlackboardWrapper modelStorage,
            ImmutableNetwork<ArchitectureNode, AttackEdge> graph) {
        final var allAttackPathsSurface = new DefaultAttackPathFinder().findAttackPaths(modelStorage,
                graph, this.crtitcalEntity);
        this.changes.getAttackpaths().addAll(toAttackPaths(modelStorage, allAttackPathsSurface));
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
    }










}
