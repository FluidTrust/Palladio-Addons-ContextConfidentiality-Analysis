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
    private final ContextTypeConverter<List<MatchType>, List<Match>> matchHandler = new MatchHandler();

    /**
     * Transform.
     *
     * @param inputModel
     *            the input model
     * @return the target type
     */
    @Override
    public TargetType transform(final List<AllOf> inputModel) {
        final var targetType = new ObjectFactory().createTargetType();
        if (!inputModel.isEmpty()) {
            final var anyOfType = new ObjectFactory().createAnyOfType();
            final var allOfList = inputModel.stream().map(this::transformAllOf).collect(Collectors.toList());

            anyOfType.getAllOf().addAll(allOfList);

            targetType.getAnyOf().add(anyOfType);
        }
        return targetType;

    }

    /**
     * Transform all of.
     *
     * @param allOf
     *            the all of
     * @return the all of type
     */
    private AllOfType transformAllOf(final AllOf allOf) {
        final var allOfType = new ObjectFactory().createAllOfType();
        final var matchList = this.matchHandler.transform(allOf.getMatch());
        allOfType.getMatch().addAll(matchList);
        return allOfType;

    }

}
