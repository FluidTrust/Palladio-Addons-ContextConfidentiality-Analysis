package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.util.List;
import java.util.stream.Collectors;

import javax.xml.bind.JAXBElement;

import org.palladiosimulator.pcm.confidentiality.context.policy.AllOf;
import org.palladiosimulator.pcm.confidentiality.context.policy.Policy;
import org.palladiosimulator.pcm.confidentiality.context.policy.PolicySet;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import com.att.research.xacml.api.XACML3;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicySetType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicyType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.TargetType;

public class PolicySetHandler implements ContextTypeConverter<PolicySetType, PolicySet> {
    private ObjectFactory factory = new ObjectFactory();

    private ContextTypeConverter<TargetType, List<AllOf>> targetHandler = new TargetHandler();

    private ContextTypeConverter<PolicyType, Policy> handler = new PolicyHandler();

    @Override
    public PolicySetType transform(PolicySet inputModel) {
        var setType = createPolicySet();

        if (inputModel == null) {
            return setType;
        }

        addPoliciesToSet(setType, inputModel);
        this.factory.createPolicyCombinerParametersType();

        setType.setPolicySetId(inputModel.getId());

        switch (inputModel.getCombiningAlgorithm()) {
        case DENY_OVERRIDES:
            setType.setPolicyCombiningAlgId(XACML3.ID_POLICY_DENY_OVERRIDES.stringValue());
            break;
        case DENY_UNLESS_PERMIT:
            setType.setPolicyCombiningAlgId(XACML3.ID_POLICY_DENY_UNLESS_PERMIT.stringValue());
            break;
        case FIRST_APPLICABLE:
            setType.setPolicyCombiningAlgId(XACML3.ID_POLICY_FIRST_APPLICABLE.stringValue());
            break;
        case ONLY_ONE_APPLICABLE:
            setType.setPolicyCombiningAlgId(XACML3.ID_POLICY_ONLY_ONE_APPLICABLE.stringValue());
            break;
        case ORDERED_DENY_OVERRIDES:
            setType.setPolicyCombiningAlgId(XACML3.ID_POLICY_ORDERED_DENY_OVERRIDES.stringValue());
            break;
        case ORDERED_PERMIT_OVERRIDES:
            setType.setPolicyCombiningAlgId(XACML3.ID_POLICY_ORDERED_PERMIT_OVERRIDES.stringValue());
            break;
        case PERMIT_OVERRIDES:
            setType.setPolicyCombiningAlgId(XACML3.ID_POLICY_PERMIT_OVERRIDES.stringValue());
            break;
        case PERMIT_UNLESS_DENY:
            setType.setPolicyCombiningAlgId(XACML3.ID_POLICY_PERMIT_UNLESS_DENY.stringValue());
            break;
        default:
            throw new IllegalStateException("unknown PolicyCombining Algorithm");
        }

        var target = this.targetHandler.transform(inputModel.getTarget());
        setType.setTarget(target);
        setType.setVersion("0.0.1");
        return setType;

    }

    private PolicySetType createPolicySet() {
        return this.factory.createPolicySetType();
    }

    private void addPoliciesToSet(PolicySetType xacmlPolicySet, PolicySet set) {
        if (set != null) {
            var listPolicy = createPolicy(set.getPolicy());
            xacmlPolicySet.getPolicySetOrPolicyOrPolicySetIdReference().addAll(listPolicy);
        }
    }

    private List<JAXBElement<PolicyType>> createPolicy(List<Policy> policies) {
        return policies.stream().map(this.handler::transform).map(this.factory::createPolicy)
                .collect(Collectors.toList());
    }

}
