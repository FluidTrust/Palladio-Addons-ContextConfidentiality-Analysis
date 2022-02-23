package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import org.eclipse.emf.common.util.URI;

import de.uka.ipd.sdq.workflow.launchconfig.AbstractWorkflowBasedRunConfiguration;

public class VariationWorkflowConfig extends AbstractWorkflowBasedRunConfiguration {
    public final static String ID_JSON_ATTACK_PATHS = "jsonAttack";
    public final static String ID_JSON_DATA = "jsonDATA";

    private final String modelFolder = "source";

    private final String scenarioFolder = "scenarios";

    private URI variationModel;


    public URI getVariationModel() {
        return this.variationModel;
    }

    public URI getModelFolder() {
        if (this.variationModel == null) {
            return null;
        }
        return this.variationModel.trimSegments(1).appendSegment(this.modelFolder);
    }

    public URI getScenarioFolder() {
        if (this.variationModel == null) {
            return null;
        }
        return this.variationModel.trimSegments(2).appendSegment(this.scenarioFolder);
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
