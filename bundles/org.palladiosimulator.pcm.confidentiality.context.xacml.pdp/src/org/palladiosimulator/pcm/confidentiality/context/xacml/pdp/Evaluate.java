package org.palladiosimulator.pcm.confidentiality.context.xacml.pdp;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

public interface Evaluate {

    boolean evaluate(List<UsageSpecification> subject, List<UsageSpecification> environment,
            List<UsageSpecification> resource, List<UsageSpecification> operation);
}
