package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.delegate;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.debug.core.ILaunch;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.AttackerAnalysisWorkflow;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ContextAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ScenarioAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.constants.Constants;

import de.uka.ipd.sdq.workflow.jobs.IJob;
import de.uka.ipd.sdq.workflow.mdsd.AbstractWorkflowBasedMDSDLaunchConfigurationDelegate;

/**
 * Launches a given launch configuration with an usage model,an allocation model and a
 * characteristics model.
 *
 * @author majuwa
 * @author Mirko Sowa
 *
 */
public class LaunchDelegate
        extends AbstractWorkflowBasedMDSDLaunchConfigurationDelegate<ContextAnalysisWorkflowConfig> {

    @Override
    protected ContextAnalysisWorkflowConfig deriveConfiguration(final ILaunchConfiguration configuration,
            final String mode) throws CoreException {
        final var output = configuration.getAttribute(Constants.ANALYSIS_TYPE_LABEL, "default");
        ContextAnalysisWorkflowConfig config = null;
        switch (output) {
        case "Scenario":
            config = new ScenarioAnalysisWorkflowConfig();
            final var scenarioBuilder = new ScenarioAnalysisConfigurationBuilder(configuration, mode);
            scenarioBuilder.fillConfiguration(config);
            break;
        case "Insider":
            config = new AttackerAnalysisWorkflowConfig();
            final var attackBuilder = new AttackAnalysisConfigurationBuilder(configuration, mode);
            attackBuilder.fillConfiguration(config);
            break;
        case "Attack surface":
            throw new UnsupportedOperationException();
        default:
            assert false;
        }
        return config;

    }

    @Override
    protected IJob createWorkflowJob(final ContextAnalysisWorkflowConfig config, final ILaunch launch)
            throws CoreException {

        // TODO make better
        if (config instanceof ScenarioAnalysisWorkflowConfig) {
            return new GUIBasedScenarioAnalysisWorkflow((ScenarioAnalysisWorkflowConfig) config);
        }
        return new AttackerAnalysisWorkflow((AttackerAnalysisWorkflowConfig) config); // FIXME
    }

}
