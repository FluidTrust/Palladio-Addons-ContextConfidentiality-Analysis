package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow;

import java.util.LinkedList;

import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.VariationWorkflowConfig;
import org.palladiosimulator.pcm.uncertainty.variation.UncertaintyVariationModel.gen.pcm.workflow.UncertaintyWorkflowJob;

import de.uka.ipd.sdq.workflow.jobs.SequentialBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

public class VariationWorkflow extends SequentialBlackboardInteractingJob<MDSDBlackboard> {
    public VariationWorkflow(VariationWorkflowConfig config) {

        var url = config.getVariationModel();

        var list = new LinkedList<>(url.segmentsList());
        list.removeLast();
        list.removeLast();

        var uri = URI.createURI("platform:/" + String.join("/", list));

        var job = new UncertaintyWorkflowJob(uri);
        this.add(job);
    }

}