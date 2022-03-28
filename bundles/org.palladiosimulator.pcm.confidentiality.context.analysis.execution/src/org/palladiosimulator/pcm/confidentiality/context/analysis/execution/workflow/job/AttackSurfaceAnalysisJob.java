package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_ATTACK;
import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_CONTEXT;
import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_PCM;

import org.eclipse.core.runtime.IProgressMonitor;
import org.palladiosimulator.analyzer.workflow.blackboard.PCMResourceSetPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.Activator;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.AttackPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ContextPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ModificationMarkPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ContextAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.IBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;
import edu.kit.ipd.sdq.attacksurface.core.AttackSurfaceAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.AttackPropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

/**
 * Job specification to launch an "attack surface" analysis. Before using the models should be loaded into
 * the corresponding MDSDBlackboard
 *
 * @author majuwa
 * @author ugnwq
 */
public class AttackSurfaceAnalysisJob implements IBlackboardInteractingJob<MDSDBlackboard> {

    private MDSDBlackboard blackboard;
    
    private static final String TEST_XACML = "test.xacml"; //TODO

    public AttackSurfaceAnalysisJob(final ContextAnalysisWorkflowConfig config) {

    }

    @Override
    public void execute(final IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        final var modificationPartition = ((ModificationMarkPartition) this.blackboard
                .getPartition(PartitionConstants.PARTITION_ID_MODIFICATION)).getModificationRepository();
        final var pcmPartition = (PCMResourceSetPartition) this.blackboard.getPartition(PARTITION_ID_PCM);
        final var system = pcmPartition.getSystem();
        final var environment = pcmPartition.getResourceEnvironment();
        final var allocation = pcmPartition.getAllocation();
        final var contextPartition = (ContextPartition) this.blackboard.getPartition(PARTITION_ID_CONTEXT);
        final var specification = contextPartition.getContextSpecification().getPcmspecificationcontainer();
        final var attackPartition = (AttackPartition) this.blackboard.getPartition(PARTITION_ID_ATTACK);
        final var vulnerabilitySpecification = attackPartition.getAttackSpecification().getSystemintegration();

        /*final var pcmXACML = new org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.PCMBlackBoard(
                pcmPartition.getSystem(), pcmPartition.getMiddlewareRepository(),
                pcmPartition.getResourceEnvironment());

        Activator.getInstance().getXACMLGenerator().generateXACML(pcmXACML, contextPartition.getContextSpecification(),
        		TEST_XACML);
        Activator.getInstance().getEvaluate().initialize(TEST_XACML);*/ //TODO
        final var wrapper = new BlackboardWrapper(modificationPartition, system, environment, allocation, specification,
                vulnerabilitySpecification, Activator.getInstance().getEvaluate());

        final var propagation = new AttackSurfaceAnalysis();//TODO inject // org.palladiosimulator.pcm.confidentiality.context.analysis.execution.Activator
        		//.getInstance().getAttackSurfaceAnalysis();//TODO inject
        propagation.runChangePropagationAnalysis(wrapper);
        //Activator.getInstance().getEvaluate().shutdown(); //TODO
    }

    @Override
    public void cleanup(final IProgressMonitor monitor) throws CleanupFailedException {
        // TODO Provide clean up Operations
    	// TODO cleanup xacml in the end and save it (per configuration)
    }

    @Override
    public String getName() {
        return "Attack Surface Analysis Job";
    }

    @Override
    public void setBlackboard(final MDSDBlackboard blackboard) {
        this.blackboard = blackboard;
    }
}
