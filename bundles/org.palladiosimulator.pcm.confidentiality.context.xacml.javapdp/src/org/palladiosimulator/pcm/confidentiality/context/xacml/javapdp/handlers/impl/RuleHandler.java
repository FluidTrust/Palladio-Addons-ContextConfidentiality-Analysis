package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.util.List;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.context.policy.Rule;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.RuleType;

@Component(service = RuleHandler.class)
public class RuleHandler implements ContextTypeConverter<List<RuleType>, List<Rule>> {

    @Override
    public List<RuleType> transform(List<Rule> inputModel) {
        // TODO Auto-generated method stub
        return null;
    }

}
