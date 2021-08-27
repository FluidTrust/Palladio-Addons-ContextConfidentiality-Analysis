package org.palladiosimulator.pcm.confidentiality.context.analysis.execution;

import org.eclipse.ui.plugin.AbstractUIPlugin;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.palladiosimulator.pcm.confidentiality.context.attackeranalysis.api.AttackerAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.ScenarioAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.XACMLGeneration;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.Evaluate;

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

    private XACMLGeneration xacmlGeneration;

    private Evaluate evaluate;

    @Override
    public void start(final BundleContext context) throws Exception {
        super.start(context);
        setInstance(instance);
        final ServiceReference<AttackerAnalysis> attackerReference = context
                .getServiceReference(AttackerAnalysis.class);
        this.attackerAnalysis = context.getService(attackerReference);
        final ServiceReference<ScenarioAnalysis> scenarioReference = context
                .getServiceReference(ScenarioAnalysis.class);
        this.scenarioAnalysis = context.getService(scenarioReference);

        final ServiceReference<XACMLGeneration> xacmlReference = context.getServiceReference(XACMLGeneration.class);
        this.xacmlGeneration = context.getService(xacmlReference);

        final ServiceReference<Evaluate> eval = context.getServiceReference(Evaluate.class);
        this.evaluate = context.getService(eval);

        instance = this;
    }

    @Override
    public void stop(final BundleContext context) throws Exception {
        setInstance(null);
        super.stop(context);
    }

    private static void setInstance(final Activator instance) {
        Activator.instance = instance;
    }

    public AttackerAnalysis getAttackerAnalysis() {
        return this.attackerAnalysis;
    }

    /**
     * Returns the scenario analyis returns null in case of no scenario analysis
     *
     * @return
     */
    public ScenarioAnalysis getScenarioAnalysis() {
        return this.scenarioAnalysis;
    }

    public XACMLGeneration getXACMLGenerator() {
        return this.xacmlGeneration;
    }

    public Evaluate getEvaluate() {
        return this.evaluate;
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
