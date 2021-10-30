package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_CONTEXT;
import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_OUTPUT;
import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_PCM;

import java.util.ArrayList;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.analyzer.workflow.blackboard.PCMResourceSetPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.Activator;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.ContextPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.OutputPartition;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ScenarioAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;

import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.IBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

/**
 * Job specification to launch an attacker analysis. Before using the models should be loaded into
 * the corresponding MDSDBlackboard
 *
 * @author majuwa
 *
 */
public class ScenarioAnalysisJob implements IBlackboardInteractingJob<MDSDBlackboard> {

    private MDSDBlackboard blackboard;
    private ScenarioAnalysisWorkflowConfig config;

    public ScenarioAnalysisJob(final ScenarioAnalysisWorkflowConfig config) {
        this.config = config;
    }

    @Override
    public void execute(final IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        final var analysis = Activator.getInstance().getScenarioAnalysis();

        final var contextPartition = (ContextPartition) this.blackboard.getPartition(PARTITION_ID_CONTEXT);
        final var pcmPartition = (PCMResourceSetPartition) this.blackboard.getPartition(PARTITION_ID_PCM);

        final var pcm = new PCMBlackBoard(pcmPartition.getSystem(), pcmPartition.getMiddlewareRepository(),
                pcmPartition.getUsageModel());
        final var pcmXACML = new org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.PCMBlackBoard(
                pcmPartition.getSystem(), pcmPartition.getMiddlewareRepository(),
                pcmPartition.getResourceEnvironment());
        var eval = Activator.getInstance().getEvaluate();

        Activator.getInstance().getXACMLGenerator().generateXACML(pcmXACML, contextPartition.getContextSpecification(),
                this.config.getOutputXACML().toFileString());

        eval.initialize(this.config.getOutputXACML().toFileString());
        final var result = analysis.runScenarioAnalysis(pcm, contextPartition.getContextSpecification(),
                new Configuration(false, eval));
        eval.shutdown();
        final var outputPartition = new OutputPartition();
        final var content = new ArrayList<EObject>(1);
        content.add(result);
        outputPartition.setContents(EcoreUtil.getURI(result), content);
        this.blackboard.addPartition(PARTITION_ID_OUTPUT, outputPartition);
    }

    @Override
    public void cleanup(final IProgressMonitor monitor) throws CleanupFailedException {
        // TODO Provide clean up Operations

    }

    @Override
    public String getName() {
        return "Scenario Analysis Job";
    }

    @Override
    public void setBlackboard(final MDSDBlackboard blackboard) {
        this.blackboard = blackboard;
    }
}
