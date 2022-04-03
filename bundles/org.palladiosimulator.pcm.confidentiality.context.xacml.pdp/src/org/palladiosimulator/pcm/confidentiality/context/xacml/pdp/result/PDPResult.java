package org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result;

import java.util.List;

/**
 * Wrapper object for access decision from the PDP
 *
 * @author majuwa
 *
 */
public record PDPResult(DecisionType decision, List<String> policyIdentifiers) {


}
