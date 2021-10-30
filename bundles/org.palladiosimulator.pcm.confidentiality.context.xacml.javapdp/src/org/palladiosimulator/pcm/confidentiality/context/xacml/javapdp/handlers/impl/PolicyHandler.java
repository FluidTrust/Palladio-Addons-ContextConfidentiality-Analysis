/*
 *
 */
package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.policy.AllOf;
import org.palladiosimulator.pcm.confidentiality.context.policy.Policy;
import org.palladiosimulator.pcm.confidentiality.context.policy.Rule;
import org.palladiosimulator.pcm.confidentiality.context.policy.VariableDefinitions;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import com.att.research.xacml.api.XACML3;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicyType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.RuleType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.TargetType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.VariableDefinitionType;

/**
 * The Class PolicyHandler.
 */
public class PolicyHandler implements ContextTypeConverter<PolicyType, Policy> {

    /** The target handler. */
    private ContextTypeConverter<TargetType, List<AllOf>> targetHandler = new TargetHandler();

    /** The rule handler. */
    private ContextTypeConverter<List<RuleType>, List<Rule>> ruleHandler = new RuleHandler();

    /** The variable handler. */
    private ContextTypeConverter<List<VariableDefinitionType>, List<VariableDefinitions>> variableHandler = new VariableDefinitionHandler();

    /**
     * Transform.
     *
     * @param policy the policy
     * @return the policy type
     */
    @Override
    public PolicyType transform(Policy policy) {
        var policyType = (new ObjectFactory()).createPolicyType();

        policyType.setPolicyId(policy.getId());
        policyType.setDescription(policy.getEntityName());

        switch (policy.getCombiningAlgorithm()) {
        case PERMIT_UNLESS_DENY:
            policyType.setRuleCombiningAlgId(XACML3.ID_RULE_PERMIT_UNLESS_DENY.stringValue());
            break;
        case DENY_OVERRIDES:
            policyType.setRuleCombiningAlgId(XACML3.ID_RULE_DENY_OVERRIDES.stringValue());
            break;
        case DENY_UNLESS_PERMIT:
            policyType.setRuleCombiningAlgId(XACML3.ID_RULE_DENY_UNLESS_PERMIT.stringValue());
            break;
        case FIRST_APPLICABLE:
            policyType.setRuleCombiningAlgId(XACML3.ID_RULE_FIRST_APPLICABLE.stringValue());
            break;
        case ONLY_ONE_APPLICABLE:
            policyType.setRuleCombiningAlgId(XACML3.ID_RULE_ONLY_ONE_APPLICABLE.stringValue());
            break;
        case ORDERED_DENY_OVERRIDES:
            policyType.setRuleCombiningAlgId(XACML3.ID_RULE_ORDERED_DENY_OVERRIDES.stringValue());
            break;
        case ORDERED_PERMIT_OVERRIDES:
            policyType.setRuleCombiningAlgId(XACML3.ID_RULE_ORDERED_PERMIT_OVERRIDES.stringValue());
            break;
        case PERMIT_OVERRIDES:
            policyType.setRuleCombiningAlgId(XACML3.ID_RULE_PERMIT_OVERRIDES.stringValue());
            break;
        default:
            throw new IllegalStateException(
                    "Unknown Combining Algorithm for Policy " + policy.getEntityName() + " with ID " + policy.getId());
        }
        var target = this.targetHandler.transform(policy.getTarget());
        policyType.setTarget(target);
        policyType.setVersion("0.0.1");

        var rules = this.ruleHandler.transform(policy.getRule());
        if (rules != null) {
            policyType.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition().addAll(rules);
        }

        var variableDefintions = this.variableHandler.transform(policy.getVariabledefinitions());
        if (variableDefintions != null) {
            policyType.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition().addAll(variableDefintions);
        }

        return policyType;
    }

}
