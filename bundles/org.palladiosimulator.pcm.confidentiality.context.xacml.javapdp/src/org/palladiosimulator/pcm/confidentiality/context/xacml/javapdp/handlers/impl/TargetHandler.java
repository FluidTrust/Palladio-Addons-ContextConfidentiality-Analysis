package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.util.List;
import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.palladiosimulator.pcm.confidentiality.context.policy.AllOf;
import org.palladiosimulator.pcm.confidentiality.context.policy.AnyOff;
import org.palladiosimulator.pcm.confidentiality.context.policy.Match;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.AllOfType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.AnyOfType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.MatchType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.TargetType;

@Component(service = TargetHandler.class)
public class TargetHandler implements ContextTypeConverter<TargetType, List<AnyOff>> {

    @Reference(service = MatchHandler.class)
    private ContextTypeConverter<List<MatchType>, List<Match>> matchHandler;

    @Override
    public TargetType transform(List<AnyOff> inputModel) {
        var targetType = new ObjectFactory().createTargetType();

        var anyOfList = inputModel.stream().map(this::transform).collect(Collectors.toList());

        targetType.getAnyOf().addAll(anyOfList);

        return targetType;

    }

    private AnyOfType transform(AnyOff anyOf) {
        var anyOfType = new ObjectFactory().createAnyOfType();

        var allOfList = anyOf.getAllof().stream().map(this::transform).collect(Collectors.toList());
        anyOfType.getAllOf().addAll(allOfList);

        return anyOfType;
    }

    private AllOfType transform(AllOf allOf) {
        var allOfType = new ObjectFactory().createAllOfType();
        var matchList = this.matchHandler.transform(allOf.getMatch());
        allOfType.getMatch().addAll(matchList);
        return allOfType;

    }

}
