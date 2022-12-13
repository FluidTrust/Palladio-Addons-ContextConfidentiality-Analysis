package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.delegate;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ClassicalAttackerAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.constants.Constants;

import de.uka.ipd.sdq.workflow.launchconfig.AbstractWorkflowBasedRunConfiguration;

/**
 * This class can build an Attacker analysis specific configuration objects out of a given Eclipse
 * Launch Configuration.
 *
 * @author majuwa
 *
 */
public class AttackAnalysisConfigurationBuilder extends ContextAnalysisConfigurationBuilder {

    public AttackAnalysisConfigurationBuilder(final ILaunchConfiguration configuration, final String mode)
            throws CoreException {
        super(configuration, mode);
    }

    @Override
    public void fillConfiguration(final AbstractWorkflowBasedRunConfiguration configuration) throws CoreException {
        super.fillConfiguration(configuration);
        if (!configuration.getClass()
            .equals(ClassicalAttackerAnalysisWorkflowConfig.class)) {
            throw new IllegalArgumentException("configuration is from type " + configuration.getClass() + ", but "
                    + ClassicalAttackerAnalysisWorkflowConfig.class + " expected");
        }
        final var config = (ClassicalAttackerAnalysisWorkflowConfig) configuration;
        config.setModificationModel(this.getURI(Constants.MODIFIACTION_MODEL_LABEL));
        config.setAttackModel(this.getURI(Constants.ATTACKER_MODEL_LABEL));
        config.setGenerateGraph(this.getBooleanAttribute(Constants.GRAPH_CREATION_LABEL));

    }

}
