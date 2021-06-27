package org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api;

import org.palladiosimulator.pcm.confidentiality.accessControl.ConfidentialAccessSpecification;

public interface XACMLGeneration {

    void generateXACML(PCMBlackBoard pcm, ConfidentialAccessSpecification confidentialitySpecification);
}
