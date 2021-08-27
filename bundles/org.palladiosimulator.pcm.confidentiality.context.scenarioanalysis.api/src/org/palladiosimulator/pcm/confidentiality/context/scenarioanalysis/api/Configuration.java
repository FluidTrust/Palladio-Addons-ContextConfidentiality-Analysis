package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api;

import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.Evaluate;

public class Configuration {
    private boolean attributeProviders;
    private Evaluate eval;

    public Configuration(boolean attributeProviders, Evaluate eval) {
        this.attributeProviders = attributeProviders;
        this.eval = eval;
    }

    public boolean isAttributeProviders() {
        return this.attributeProviders;
    }

    public Evaluate getEvaluate() {
        return this.eval;
    }

}
