package org.palladiosimulator.pcm.confidentiality.context.analysis.ui;

import org.eclipse.jface.resource.ImageDescriptor;
import org.eclipse.ui.plugin.AbstractUIPlugin;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.palladiosimulator.pcm.confidentiality.context.analysis.api.Analysis;

/**
 * The activator class controls the plug-in life cycle.
 * 
 * @author majuwa
 * @version 1.00
 */
public class Activator extends AbstractUIPlugin {

    // The plug-in ID
    public static final String PLUGIN_ID = 
            "org.palladiosimulator.pcm.confidentiality.context.attackeranalysis.ui"; //$NON-NLS-1$
    
    // The shared instance
    private static Activator instance;
    private Analysis analysis;
    /**
     * The constructor
     */
    public Activator() {
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.eclipse.ui.plugin.AbstractUIPlugin#start(org.osgi.framework.BundleContext)
     */
    @Override
    public void start(BundleContext context) throws Exception {
        super.start(context);
        
        ServiceReference<Analysis> reference = context.getServiceReference(Analysis.class);
        analysis = context.getService(reference);
        instance = this;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.eclipse.ui.plugin.AbstractUIPlugin#stop(org.osgi.framework.BundleContext)
     */
    @Override
    public void stop(BundleContext context) throws Exception {
        instance = null;
        super.stop(context);
    }

    /**
     * Returns the shared instance
     *
     * @return the shared instance
     */
    public static Activator getInstance() {
        return instance;
    }

    /**
     * Returns an image descriptor for the image file at the given plug-in relative path
     *
     * @param path
     *            the path
     * @return the image descriptor
     */
    public static ImageDescriptor getImageDescriptor(String path) {
        return imageDescriptorFromPlugin(PLUGIN_ID, path);
    }
    public Analysis getAnalysis() {
        return analysis;
    }
}
