package edu.kit.ipd.sdq.kamp4attack.core;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ModificationMarkPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants;

import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;
import edu.kit.ipd.sdq.kamp.architecture.AbstractArchitectureVersion;
import edu.kit.ipd.sdq.kamp4attack.model.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository;

/**
 * This class wraps the MDSD Blackboard {@link MDSDBlackboard}
 * 
 * 
 * @author Maximilian Walter
 *
 */

public class BlackboardWrapper extends AbstractArchitectureVersion<AbstractKAMP4attackModificationRepository<?>> {

    private MDSDBlackboard blackboard;

    public BlackboardWrapper(MDSDBlackboard blackboard) {
        super("", ((ModificationMarkPartition) blackboard.getPartition(PartitionConstants.PARTITION_ID_MODIFICATION))
                .getModificationRepository());
        this.blackboard = blackboard;
    }

    // TODO add necessary getters for Blackboard

}
