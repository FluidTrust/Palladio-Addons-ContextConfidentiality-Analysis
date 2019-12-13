package org.palladiosimulator.pcm.confidentiality.context.analysis.provider.helper;

import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.resource.ResourceSet;
import org.eclipse.emf.ecore.resource.impl.ResourceSetImpl;
import org.palladiosimulator.pcm.confidentiality.context.model.Context;
import org.palladiosimulator.pcm.usagemodel.UsageModel;

public class ModelLoader {
    private ResourceSet resourceSet;
    
    public ModelLoader() {
        resourceSet = new ResourceSetImpl();
    }
    public Context getContextModel(URI path) {
        return (Context) loadResource(resourceSet, path);
    }
    public UsageModel getUsageModel(URI path) {
        return (UsageModel) loadResource(resourceSet, path);
    }
    /**
     * Loads a resource.
     * 
     * @param resourceSet - the resource set
     * @param path - the path
     * @return the resource
     */
    private EObject loadResource(final ResourceSet resourceSet, final URI path) {
        return resourceSet.getResource(path, true).getContents().get(0);
    }
}
