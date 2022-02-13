package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config;

import org.eclipse.emf.common.util.URI;

import de.uka.ipd.sdq.workflow.launchconfig.AbstractWorkflowBasedRunConfiguration;

public class VariationWorkflowConfig extends AbstractWorkflowBasedRunConfiguration {
    private URI variationModel;

    public URI getVariationModel() {
        return this.variationModel;
    }

    public void setVariationModel(URI variationModel) {
        this.variationModel = variationModel;
    }

    @Override
    public String getErrorMessage() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void setDefaults() {
        // TODO Auto-generated method stub

    }

}
