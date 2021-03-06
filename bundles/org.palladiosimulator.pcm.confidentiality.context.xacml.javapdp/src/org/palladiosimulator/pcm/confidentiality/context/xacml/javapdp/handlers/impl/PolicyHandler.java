package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.util.List;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.palladiosimulator.pcm.confidentiality.context.policy.AnyOff;
import org.palladiosimulator.pcm.confidentiality.context.policy.Policy;
import org.palladiosimulator.pcm.confidentiality.context.policy.Rule;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import com.att.research.xacml.api.XACML3;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicyType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.RuleType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.TargetType;

@Component(name = "PolicyHandler", service = PolicyHandler.class)
public class PolicyHandler implements ContextTypeConverter<PolicyType, Policy> {

    @Reference(service = TargetHandler.class)
    private ContextTypeConverter<TargetType, List<AnyOff>> targetHandler;
    @Reference(service = RuleHandler.class)
    private ContextTypeConverter<List<RuleType>, List<Rule>> ruleHandler;

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

        var rules = this.ruleHandler.transform(policy.getRule());
        policyType.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition().addAll(rules);

        return policyType;
    }

}
