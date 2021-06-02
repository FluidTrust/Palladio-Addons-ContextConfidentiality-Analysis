package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api;

public class Configuration {
    private boolean attributeProviders;
    
    public Configuration(boolean attributeProviders) {
        this.attributeProviders = attributeProviders;
    }
    
    public boolean isAttributeProviders() {
        return attributeProviders;
    }

}
