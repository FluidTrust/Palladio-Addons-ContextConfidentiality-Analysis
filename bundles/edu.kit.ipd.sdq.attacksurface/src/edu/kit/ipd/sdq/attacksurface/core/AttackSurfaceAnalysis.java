package edu.kit.ipd.sdq.attacksurface.core;

import java.util.logging.Logger;

import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraphCreation;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.api.IAttackPropagationAnalysis;
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

        this.createInitialStructure(modelStorage);
        final var graph = new AttackGraphCreation(modelStorage);

        graph.createGraph();

        (new AttackPathCreation(this.crtitcalEntity, this.changes)).createAttackPaths(modelStorage, graph.getGraph());
        VulnerabilityHelper.resetMap();

    }

    private void createInitialStructure(final BlackboardWrapper board) {
        final var repository = board.getModificationMarkRepository();
        final var localAttacker = AttackHandlingHelper.getSurfaceAttacker(board);

        repository.getChangePropagationSteps()
            .clear();

        final var criticalPCMElement = localAttacker.getTargetedElement();
        this.crtitcalEntity = PCMElementType.typeOf(criticalPCMElement)
            .getEntity(criticalPCMElement);

        board.getModificationMarkRepository()
            .getChangePropagationSteps()
            .add(this.changes);
    }

}
