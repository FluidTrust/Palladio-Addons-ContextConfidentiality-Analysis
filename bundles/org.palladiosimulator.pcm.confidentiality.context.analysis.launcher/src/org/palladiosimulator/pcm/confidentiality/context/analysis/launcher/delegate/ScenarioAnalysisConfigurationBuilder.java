package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.delegate;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ScenarioAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.constants.Constants;

import de.uka.ipd.sdq.workflow.launchconfig.AbstractWorkflowBasedRunConfiguration;

/**
 * This class can build an Attacker analysis specific configuration objects out of a given Eclipse
 * Launch Configuration.
 *
 * @author majuwa
 *
 */
public class ScenarioAnalysisConfigurationBuilder extends ContextAnalysisConfigurationBuilder {

    public ScenarioAnalysisConfigurationBuilder(final ILaunchConfiguration configuration, final String mode)
            throws CoreException {
        super(configuration, mode);
    }

    @Override
    public void fillConfiguration(final AbstractWorkflowBasedRunConfiguration configuration) throws CoreException {
        super.fillConfiguration(configuration);
        if (!configuration.getClass().equals(ScenarioAnalysisWorkflowConfig.class)) {
            throw new IllegalArgumentException("configuration is from type " + configuration.getClass() + ", but "
                    + ScenarioAnalysisWorkflowConfig.class + " expected");
        }
        final var config = (ScenarioAnalysisWorkflowConfig) configuration;
        config.setUsage(getURI(Constants.USAGE_MODEL_LABEL));

    }

}
