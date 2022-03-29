package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ClassicalAttackerAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.AttackerAnalysisJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.CreateGraphJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadAttackerModel;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadContextJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadModificationMarkJob;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.LoadPCMAttack;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.job.VulnerabilityRollOutComponentsJob;

import de.uka.ipd.sdq.workflow.jobs.IJob;
import de.uka.ipd.sdq.workflow.jobs.SequentialBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

/**
 * Workflow for AttackerAnalysis
 *
 * @author majuwa
 *
 *
 */
public abstract class AttackerAnalysisWorkflow extends SequentialBlackboardInteractingJob<MDSDBlackboard> {

    public AttackerAnalysisWorkflow(final ClassicalAttackerAnalysisWorkflowConfig config) {
        super(false);
        this.add(new LoadPCMAttack(config));
        this.add(new LoadContextJob(config));
        this.add(new LoadAttackerModel(config));
        this.add(new VulnerabilityRollOutComponentsJob());
        this.add(new LoadModificationMarkJob(config));
        this.add(new AttackerAnalysisJob(config));
        if (config.getGenerateGraph()) {
            this.add(new CreateGraphJob(config));
        }
        getOutputJob().stream().forEach(this::add);
    }

    protected abstract List<IJob> getOutputJob();
}
