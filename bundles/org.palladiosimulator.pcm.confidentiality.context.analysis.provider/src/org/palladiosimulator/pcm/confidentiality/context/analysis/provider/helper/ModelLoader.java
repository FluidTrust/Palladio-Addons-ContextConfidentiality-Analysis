package org.palladiosimulator.pcm.confidentiality.context.analysis.provider.helper;

import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.resource.ResourceSet;
import org.eclipse.emf.ecore.resource.impl.ResourceSetImpl;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.usagemodel.UsageModel;

public class ModelLoader {
    private ResourceSet resourceSet;
    
    public ModelLoader() {
        resourceSet = new ResourceSetImpl();
    }
    public ConfidentialAccessSpecification getContextModel(URI path) {
        return (ConfidentialAccessSpecification) loadResource(resourceSet, path);
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
