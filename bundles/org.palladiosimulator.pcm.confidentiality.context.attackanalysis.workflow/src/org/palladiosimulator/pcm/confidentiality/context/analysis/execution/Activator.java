package org.palladiosimulator.pcm.confidentiality.context.analysis.execution;

import org.eclipse.ui.plugin.AbstractUIPlugin;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.palladiosimulator.pcm.confidentiality.context.analysis.api.ContextAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.attackeranalysis.api.AttackerAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.ScenarioAnalysis;

/**
 * The activator class controls the plug-in life cycle
 */
public class Activator extends AbstractUIPlugin {

	// The plug-in ID
	public static final String PLUGIN_ID = "pcm.dataprocessing.analysis.wfe"; //$NON-NLS-1$

	// The shared instance
	private static Activator instance;

    private AttackerAnalysis attackerAnalysis;
    private ScenarioAnalysis scenarioAnalysis;

	@Override
	public void start(BundleContext context) throws Exception {
		super.start(context);
		setInstance(instance);
		ServiceReference<AttackerAnalysis> attackerReference = context.getServiceReference(AttackerAnalysis.class);
        attackerAnalysis = context.getService(attackerReference);
        ServiceReference<ScenarioAnalysis> scenarioReference = context.getServiceReference(ScenarioAnalysis.class);
        scenarioAnalysis = context.getService(scenarioReference);
        instance = this;
	}

	@Override
	public void stop(BundleContext context) throws Exception {
		setInstance(null);
		super.stop(context);
	}


	private static void setInstance(Activator instance) {
		Activator.instance = instance;
	}
	
	public AttackerAnalysis getAttackerAnalysis() {
	    return attackerAnalysis;
	}
	
	/**
	 * Returns the scenario analyis returns null in case of no scenario analysis
	 * @return
	 */
	public ScenarioAnalysis getScenarioAnalysis() {
	    return scenarioAnalysis;
	}
	
	/**
	 * Returns the shared instance
	 *
	 * @return the shared instance
	 */
	public static Activator getInstance() {
		return Activator.instance;
	}

	
}
