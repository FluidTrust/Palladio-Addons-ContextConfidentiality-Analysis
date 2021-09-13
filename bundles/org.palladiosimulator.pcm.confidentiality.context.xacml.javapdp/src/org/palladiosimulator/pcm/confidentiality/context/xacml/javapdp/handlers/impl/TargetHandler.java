/*
 *
 */
package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.util.List;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.context.policy.AllOf;
import org.palladiosimulator.pcm.confidentiality.context.policy.Match;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.AllOfType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.MatchType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.TargetType;

/**
 * The Class TargetHandler.
 */
public class TargetHandler implements ContextTypeConverter<TargetType, List<AllOf>> {

    /** The match handler. */
    private ContextTypeConverter<List<MatchType>, List<Match>> matchHandler = new MatchHandler();

    /**
     * Transform.
     *
     * @param inputModel the input model
     * @return the target type
     */
    @Override
    public TargetType transform(List<AllOf> inputModel) {
        var targetType = new ObjectFactory().createTargetType();
        if (!inputModel.isEmpty()) {
            var anyOfType = new ObjectFactory().createAnyOfType();
            var allOfList = inputModel.stream().map(this::transformAllOf).collect(Collectors.toList());

            anyOfType.getAllOf().addAll(allOfList);

            targetType.getAnyOf().add(anyOfType);
        }
        return targetType;

    }

    /**
     * Transform all of.
     *
     * @param allOf the all of
     * @return the all of type
     */
    private AllOfType transformAllOf(AllOf allOf) {
        var allOfType = new ObjectFactory().createAllOfType();
        var matchList = this.matchHandler.transform(allOf.getMatch());
        allOfType.getMatch().addAll(matchList);
        return allOfType;

    }

}
