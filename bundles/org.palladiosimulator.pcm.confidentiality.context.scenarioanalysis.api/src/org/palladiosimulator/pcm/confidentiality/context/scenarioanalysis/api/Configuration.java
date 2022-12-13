package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api;

import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.Evaluate;

public class Configuration {
    private final boolean attributeProviders;
    private final Evaluate eval;

    public Configuration(final boolean attributeProviders, final Evaluate eval) {
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
