package org.palladiosimulator.pcm.confidentiality.context.xacml.pdp;

import java.util.List;
import java.util.Optional;

import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;

public interface Evaluate {

    boolean initialize(String pathXACMLFile);

    void shutdown();

    Optional<PDPResult> evaluate(List<UsageSpecification> subject, List<UsageSpecification> environment,
            List<UsageSpecification> resource, List<UsageSpecification> operation,
            List<UsageSpecification> xacmlAttribute);
}
