/*
 *
 */
package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.util.List;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.context.policy.AllOf;
import org.palladiosimulator.pcm.confidentiality.context.policy.Expression;
import org.palladiosimulator.pcm.confidentiality.context.policy.Rule;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.ConditionType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.EffectType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.RuleType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.TargetType;

public class RuleHandler implements ContextTypeConverter<List<RuleType>, List<Rule>> {

    private ObjectFactory factory = new ObjectFactory();

    private ContextTypeConverter<TargetType, List<AllOf>> targetHandler = new TargetHandler();

    private ContextTypeConverter<ConditionType, Expression> conditionHandler = new ConditionHandler();

    @Override
    public List<RuleType> transform(List<Rule> inputModel) {
        return inputModel.stream().map(this::createRule).collect(Collectors.toList());
    }

    private RuleType createRule(Rule rule) {
        var ruleType = this.factory.createRuleType();
        ruleType.setDescription(rule.getEntityName());
        ruleType.setRuleId(rule.getId());

        switch (rule.getPermit()) {
        case DENY:
            ruleType.setEffect(EffectType.DENY);
            break;
        case PERMIT:
            ruleType.setEffect(EffectType.PERMIT);
            break;
        default:
            throw new IllegalStateException("Unknown Effect/Permit type");
        }

        var target = this.targetHandler.transform(rule.getTarget());
        ruleType.setTarget(target);

        if (rule.getCondition() != null) {
            var condition = this.conditionHandler.transform(rule.getCondition());
            ruleType.setCondition(condition);
        }

        return ruleType;
    }

}
