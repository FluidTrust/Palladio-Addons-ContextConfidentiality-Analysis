package edu.kit.ipd.sdq.kamp4attack.core;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_CONTEXT;
import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_PCM;

import org.palladiosimulator.analyzer.workflow.blackboard.PCMResourceSetPartition;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ContextPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ModificationMarkPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants;
import org.palladiosimulator.pcm.confidentiality.context.specification.PCMSpecificationContainer;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.system.System;

import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;
import edu.kit.ipd.sdq.kamp.architecture.AbstractArchitectureVersion;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository;

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

    /**
     * Gets the {@link System} 
     * @return Returns the system of the current PCM model 
     */
    public System getAssembly() {
        final var pcmPartition = (PCMResourceSetPartition) this.blackboard.getPartition(PARTITION_ID_PCM);
        return pcmPartition.getSystem();
    }
    
    public ResourceEnvironment getResourceEnvironment() {
        final var pcmPartition = (PCMResourceSetPartition) this.blackboard.getPartition(PARTITION_ID_PCM);
        return pcmPartition.getResourceEnvironment();
    }
    
    public Allocation getAllocation() {
        final var pcmPartition = (PCMResourceSetPartition) this.blackboard.getPartition(PARTITION_ID_PCM);
        return pcmPartition.getAllocation();
    }
    
    
    public PCMSpecificationContainer getSpecification() {
        final var contextPartition = (ContextPartition) this.blackboard.getPartition(PARTITION_ID_CONTEXT);
        return contextPartition.getContextSpecification().getPcmspecificationcontainer();
    }

    // TODO add necessary getters for Blackboard

}
