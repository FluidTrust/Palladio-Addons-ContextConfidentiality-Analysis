package org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api;

import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;

public interface XACMLGeneration {

    void generateXACML(PCMBlackBoard pcm, ConfidentialAccessSpecification confidentialitySpecification, String path);
}
