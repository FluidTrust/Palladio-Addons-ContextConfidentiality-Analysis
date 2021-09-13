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
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ConnectionRestriction;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.EntityMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.GenericMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.HierarchicalContext;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.MethodMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
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
    public List<MatchType> transform(List<Match> inputModel) {
        final var factory = new ObjectFactory();

        var switchMatch = new StructureSwitch<Stream<MatchType>>() {
            @Override
            public Stream<MatchType> caseEntityMatch(EntityMatch match) {
                final var matchType = factory.createMatchType();
                matchType.setMatchId(XACML3.ID_FUNCTION_STRING_EQUAL.stringValue());

                setResource(match.getEntity(), matchType, match.getCategory());

                return Stream.of(matchType);

            }

            private void setResource(Entity entity, final MatchType matchType, Category category,
                    HierarchicalContext context) {
                createResourceDesignatorInMatch(matchType, category);

                var value = factory.createAttributeValueType();
                value.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                if (entity instanceof AssemblyContext || entity instanceof Connector) {
                    addHierachy(context, value);
                }
                value.getContent().add(entity.getId());
                value.getContent().add(entity.getEntityName());

                matchType.setAttributeValue(value);
            }

            private void setResource(Entity entity, final MatchType matchType, Category category) {
                setResource(entity, matchType, category, null);
            }

            private void createResourceDesignatorInMatch(final MatchType matchType, Category category) {

                var designator = createDesignator(XACML3.ID_RESOURCE_RESOURCE_ID, category);

                matchType.setAttributeDesignator(designator);
            }

            @Override
            public Stream<MatchType> caseGenericMatch(GenericMatch object) {
                final var matchType = factory.createMatchType();
                EnumHelpers.extractAndSetFunction(object.getOperation(), matchType::setMatchId);
                var designator = factory.createAttributeDesignatorType();

                // get the attribute id
                var container = (Attribute) object.getAttributevalue().eContainer();
                designator.setAttributeId(container.getId());
                if (container instanceof SystemEntityAttribute) { // identify issuer
                    designator.setIssuer(((SystemEntityAttribute) container).getModelEntity().getId());
                }
                var value = factory.createAttributeValueType();
                EnumHelpers.extractAndSetCategory(object.getCategory(), designator::setCategory);

                EnumHelpers.extractAndSetDataType(object.getAttributevalue().getType(), designator::setDataType);
                EnumHelpers.extractAndSetDataType(object.getAttributevalue().getType(), value::setDataType);

                switch (object.getOperation()) {
                case STRING_EQUAL:
                    matchType.setMatchId(XACML3.ID_FUNCTION_STRING_EQUAL.stringValue());
                    break;
                default:
                    throw new IllegalStateException("Method " + object.getOperation() + " not implemented yet");

                }

                value.getContent().addAll(object.getAttributevalue().getValues());

                matchType.setAttributeDesignator(designator);
                matchType.setAttributeValue(value);
                return Stream.of(matchType);

            }

            @Override
            public Stream<MatchType> caseMethodMatch(MethodMatch match) {
                final var matchActionType = factory.createMatchType();

                var designator = createDesignator(XACML3.ID_ACTION_ACTION_ID, Category.ACTION);
                matchActionType.setAttributeDesignator(designator);
                match.getMethodspecification();
                designator.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                EnumHelpers.extractAndSetFunction(Operations.STRING_EQUAL, matchActionType::setMatchId);

                var value = factory.createAttributeValueType();
                value.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                value.getContent().add(match.getMethodspecification().getSignature().getId());
                matchActionType.setAttributeValue(value);

                var matchResourceType = factory.createMatchType();
                EnumHelpers.extractAndSetFunction(Operations.STRING_EQUAL, matchResourceType::setMatchId);

                if (match.getMethodspecification() instanceof ConnectionRestriction) {
                    var restriction = (ConnectionRestriction) match.getMethodspecification();
                    setResource(restriction.getConnector(), matchResourceType, Category.RESOURCE, match);

                } else if (match.getMethodspecification() instanceof ServiceRestriction) {
                    var restriction = (ServiceRestriction) match.getMethodspecification();
                    createResourceDesignatorInMatch(matchResourceType, Category.RESOURCE);
                    var resourceValue = factory.createAttributeValueType();
                    resourceValue.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                    resourceValue.getContent().add(restriction.getAssemblycontext().getId());
                    addHierachy(match, resourceValue);
                    resourceValue.getContent().add(restriction.getAssemblycontext().getEntityName());
                    matchResourceType.setAttributeValue(resourceValue);
                }

                return Stream.of(matchActionType, matchResourceType);

            }

            private void addHierachy(HierarchicalContext context, AttributeValueType resourceValue) {
                if (context == null) {
                    return;
                }
                context.getHierachy().stream().map(AssemblyContext::getId).forEach(resourceValue.getContent()::add);
            }

            @Override
            public Stream<MatchType> caseXMLMatch(XMLMatch match) {
                MatchType matchType;
                try {
                    var context = ContextFactory.createContext(new Class[] { MatchType.class }, null);
                    var unmarshall = context.createUnmarshaller();
                    @SuppressWarnings("unchecked")
                    var privateObject = (JAXBElement<MatchType>) unmarshall
                    .unmarshal(new StringReader(match.getXmlString()));
                    matchType = privateObject.getValue();
                    return Stream.of(matchType);

                } catch (JAXBException e) {
                    throw new IllegalStateException(e.getMessage());
                }

            }

            private AttributeDesignatorType createDesignator(Identifier attributeID, Category category) {
                var designator = factory.createAttributeDesignatorType();
                EnumHelpers.extractAndSetCategory(category, designator::setCategory);
                designator.setAttributeId(attributeID.stringValue());
                designator.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                return designator;
            }

        };

        return inputModel.stream().flatMap(switchMatch::doSwitch).collect(Collectors.toList());

    }

}
