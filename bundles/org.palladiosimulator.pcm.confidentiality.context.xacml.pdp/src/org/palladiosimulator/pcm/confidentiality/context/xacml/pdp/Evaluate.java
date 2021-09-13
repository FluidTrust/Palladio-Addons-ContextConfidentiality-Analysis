package org.palladiosimulator.pcm.confidentiality.context.xacml.pdp;

import java.util.List;
import java.util.Optional;

import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;

/**
 * Interface for an evaluation context of ABAC policies based on a PDP
 *
 * @author majuwa
 *
 */
public interface Evaluate {

    /**
     * Initialise the ABAC-PDP with the given XACML policy file
     *
     * @param pathXACMLFile
     *            path to XACML file
     * @return true if init was successful
     */
    boolean initialize(String pathXACMLFile);

    /**
     * Shutdowns the evaluation context. Before shutdown the {@link Evaluate.initialize} must be
     * executed
     */
    void shutdown();

    /**
     * Evaluates the given attribute set at the PDP
     *
     * @param subject
     *            subject attributes
     * @param environment
     *            environment attributes
     * @param resource
     *            resource attributes
     * @param operation
     *            operation attributes
     * @param xacmlAttribute
     *            custom XACMl attributes based on xml strings
     * @return decision of PDP
     */
    Optional<PDPResult> evaluate(List<UsageSpecification> subject, List<UsageSpecification> environment,
            List<UsageSpecification> resource, List<UsageSpecification> operation,
            List<UsageSpecification> xacmlAttribute);
}
