package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.io.StringReader;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import org.palladiosimulator.pcm.confidentiality.context.policy.Category;
import org.palladiosimulator.pcm.confidentiality.context.policy.Match;
import org.palladiosimulator.pcm.confidentiality.context.policy.Operations;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ConnectionSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.EntityMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.GenericMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.MethodMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.XMLMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.util.StructureSwitch;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.Attribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemEntityAttribute;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util.EnumHelpers;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.Connector;
import org.palladiosimulator.pcm.core.entity.Entity;

import com.att.research.xacml.api.Identifier;
import com.att.research.xacml.api.XACML3;
import com.sun.xml.bind.v2.ContextFactory;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributeDesignatorType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributeValueType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.MatchType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;

public class MatchHandler implements ContextTypeConverter<List<MatchType>, List<Match>> {

    @Override
    public List<MatchType> transform(final List<Match> inputModel) {
        final var factory = new ObjectFactory();

        final var switchMatch = new StructureSwitch<Stream<MatchType>>() {
            @Override
            public Stream<MatchType> caseEntityMatch(final EntityMatch match) {
                final var matchType = factory.createMatchType();
                matchType.setMatchId(XACML3.ID_FUNCTION_STRING_EQUAL.stringValue());

                this.setResource(match.getEntity(), matchType, match.getCategory(), match.getHierachy());

                return Stream.of(matchType);

            }

            private void setResource(final Entity entity, final MatchType matchType, final Category category,
                    final List<AssemblyContext> context) {
                this.createResourceDesignatorInMatch(matchType, category);

                final var value = factory.createAttributeValueType();
                value.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                if (entity instanceof AssemblyContext || entity instanceof Connector) {
                    this.addHierachy(context, value);
                }
                value.getContent()
                    .add(entity.getId());
                value.getContent()
                    .add(entity.getEntityName());

                matchType.setAttributeValue(value);
            }

            private void createResourceDesignatorInMatch(final MatchType matchType, final Category category) {

                final var designator = this.createDesignator(XACML3.ID_RESOURCE_RESOURCE_ID, category);

                matchType.setAttributeDesignator(designator);
            }

            @Override
            public Stream<MatchType> caseGenericMatch(final GenericMatch object) {
                final var matchType = factory.createMatchType();
                EnumHelpers.extractAndSetFunction(object.getOperation(), matchType::setMatchId);
                final var designator = factory.createAttributeDesignatorType();

                // get the attribute id
                final var container = (Attribute) object.getAttributevalue()
                    .eContainer();
                designator.setAttributeId(container.getId());
                if (container instanceof SystemEntityAttribute) { // identify issuer
                    designator.setIssuer(((SystemEntityAttribute) container).getModelEntity()
                        .getId());
                }
                final var value = factory.createAttributeValueType();
                EnumHelpers.extractAndSetCategory(object.getCategory(), designator::setCategory);

                EnumHelpers.extractAndSetDataType(object.getAttributevalue()
                    .getType(), designator::setDataType);
                EnumHelpers.extractAndSetDataType(object.getAttributevalue()
                    .getType(), value::setDataType);

                switch (object.getOperation()) {
                case STRING_EQUAL:
                    matchType.setMatchId(XACML3.ID_FUNCTION_STRING_EQUAL.stringValue());
                    break;
                default:
                    throw new IllegalStateException("Method " + object.getOperation() + " not implemented yet");

                }

                value.getContent()
                    .addAll(object.getAttributevalue()
                        .getValues());

                matchType.setAttributeDesignator(designator);
                matchType.setAttributeValue(value);
                return Stream.of(matchType);

            }

            @Override
            public Stream<MatchType> caseMethodMatch(final MethodMatch match) {
                final var matchActionType = factory.createMatchType();

                final var designator = this.createDesignator(XACML3.ID_ACTION_ACTION_ID, Category.ACTION);
                matchActionType.setAttributeDesignator(designator);
                match.getMethodspecification();
                designator.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                EnumHelpers.extractAndSetFunction(Operations.STRING_EQUAL, matchActionType::setMatchId);

                final var value = factory.createAttributeValueType();
                value.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                value.getContent()
                    .add(match.getMethodspecification()
                        .getSignature()
                        .getId());
                matchActionType.setAttributeValue(value);

                final var matchResourceType = factory.createMatchType();
                EnumHelpers.extractAndSetFunction(Operations.STRING_EQUAL, matchResourceType::setMatchId);

                if (match.getMethodspecification() instanceof final ConnectionSpecification restriction) {
                    this.setResource(restriction.getConnector(), matchResourceType, Category.RESOURCE,
                            restriction.getHierarchy());

                } else if (match.getMethodspecification() instanceof final ServiceSpecification restriction) {
                    this.createResourceDesignatorInMatch(matchResourceType, Category.RESOURCE);
                    final var resourceValue = factory.createAttributeValueType();
                    resourceValue.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                    this.addHierachy(match.getMethodspecification()
                        .getHierarchy(), resourceValue);
                    resourceValue.getContent()
                        .add(restriction.getAssemblycontext()
                            .getId());
                    resourceValue.getContent()
                        .add(restriction.getAssemblycontext()
                            .getEntityName());
                    matchResourceType.setAttributeValue(resourceValue);
                }

                return Stream.of(matchActionType, matchResourceType);

            }

            private void addHierachy(final List<AssemblyContext> context, final AttributeValueType resourceValue) {
                if (context == null) {
                    return;
                }
                context.stream()
                    .map(AssemblyContext::getId)
                    .forEach(resourceValue.getContent()::add);
            }

            @Override
            public Stream<MatchType> caseXMLMatch(final XMLMatch match) {
                MatchType matchType;
                try {
                    final var context = ContextFactory.createContext(new Class[] { MatchType.class }, null);
                    final var unmarshall = context.createUnmarshaller();
                    @SuppressWarnings("unchecked")
                    final var privateObject = (JAXBElement<MatchType>) unmarshall
                        .unmarshal(new StringReader(match.getXmlString()));
                    matchType = privateObject.getValue();
                    return Stream.of(matchType);

                } catch (final JAXBException e) {
                    throw new IllegalStateException(e.getMessage());
                }

            }

            private AttributeDesignatorType createDesignator(final Identifier attributeID, final Category category) {
                final var designator = factory.createAttributeDesignatorType();
                EnumHelpers.extractAndSetCategory(category, designator::setCategory);
                designator.setAttributeId(attributeID.stringValue());
                designator.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                return designator;
            }

        };

        return inputModel.stream()
            .flatMap(switchMatch::doSwitch)
            .collect(Collectors.toList());

    }

}
