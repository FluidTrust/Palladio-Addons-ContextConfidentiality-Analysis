package org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result;

import java.util.List;

public final class PDPResult {

    private final DecisionType decision;

    private final List<String> policyIdentifiers;

    public PDPResult(final DecisionType decision, final List<String> policyIdentifiers) {
        this.decision = decision;
        this.policyIdentifiers = policyIdentifiers;
    }

    public DecisionType getDecision() {
        return this.decision;
    }

    public List<String> getPolicyIdentifiers() {
        return this.policyIdentifiers;
    }

}
