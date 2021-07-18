package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.impl;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.context.policy.Category;
import org.palladiosimulator.pcm.confidentiality.context.policy.Match;
import org.palladiosimulator.pcm.confidentiality.context.policy.XMLString;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ConnectionRestriction;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.EntityMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.GenericMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.MethodMatch;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ProvidedRestriction;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.util.StructureSwitch;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.Attribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemEntityAttribute;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.handlers.ContextTypeConverter;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util.EnumHelpers;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

import com.att.research.xacml.api.Identifier;
import com.att.research.xacml.api.XACML3;
import com.sun.xml.bind.v2.ContextFactory;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributeDesignatorType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.MatchType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;

@Component(service = MatchHandler.class)
public class MatchHandler implements ContextTypeConverter<List<MatchType>, List<Match>> {

    private static final Logger LOGGER = Logger.getLogger(MatchHandler.class.getName());

    @Override
    public List<MatchType> transform(List<Match> inputModel) {
        final var factory = new ObjectFactory();

        var switchMatch = new StructureSwitch<Stream<MatchType>>() {
            @Override
            public Stream<MatchType> caseEntityMatch(EntityMatch match) {
                final var matchType = factory.createMatchType();
                matchType.setMatchId(match.getId());

                setResource(match.getEntity(), matchType, match.getCategory());

                return Stream.of(matchType);

            }

            private void setResource(Entity entity, final MatchType matchType, Category category) {
                createResourceDesignatorInMatch(matchType, category);

                var value = factory.createAttributeValueType();
                value.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                value.getContent().add(entity.getId());
                value.getContent().add(entity.getEntityName());

                matchType.setAttributeValue(value);
            }

            private void createResourceDesignatorInMatch(final MatchType matchType, Category category) {

                var designator = createDesignator(XACML3.ID_RESOURCE_RESOURCE_ID, category);

                matchType.setAttributeDesignator(designator);
            }

            @Override
            public Stream<MatchType> caseGenericMatch(GenericMatch object) {
                final var matchType = factory.createMatchType();
                matchType.setMatchId(object.getId());
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
                    break;

                }

                value.getContent().add(object.getAttributevalue().getValue());

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
                matchActionType.setMatchId(match.getId());

                var value = factory.createAttributeValueType();
                value.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                value.getContent().add(match.getMethodspecification().getSignature().getId());
                matchActionType.setAttributeValue(value);

                var matchResourceType = factory.createMatchType();
                matchResourceType.setMatchId(match.getId() + match.getEntityName());
                if (match.getMethodspecification() instanceof ConnectionRestriction) {
                    var restriction = (ConnectionRestriction) match.getMethodspecification();
                    setResource(restriction.getConnector(), matchResourceType, Category.RESOURCE);

                } else if (match.getMethodspecification() instanceof ProvidedRestriction) {
                    var restriction = (ProvidedRestriction) match.getMethodspecification();
                    createResourceDesignatorInMatch(matchResourceType, Category.RESOURCE);
                    var resourceValue = factory.createAttributeValueType();
                    resourceValue.setDataType(XACML3.ID_DATATYPE_STRING.stringValue());
                    getComponentHierarchy(restriction.getAssemblycontext()).stream().map(AssemblyContext::getId)
                            .forEach(resourceValue.getContent()::add);
                    resourceValue.getContent().add(restriction.getProvidedrole().getId());
                    matchResourceType.setAttributeValue(resourceValue);
                }

                return Stream.of(matchActionType, matchResourceType);

            }

            @Override
            public Stream<MatchType> caseXMLString(XMLString match) {
                MatchType matchType;
                try {
                    var context = ContextFactory.createContext(new Class[] { MatchType.class }, null);
                    var unmarshall = context.createUnmarshaller();
                    var privateObject = (JAXBElement<MatchType>) unmarshall
                            .unmarshal(new StringReader(match.getString()));
                    matchType = privateObject.getValue();
                    return Stream.of(matchType);

                } catch (JAXBException e) {
                    LOGGER.log(Level.SEVERE, e.getMessage());
                    throw new IllegalStateException(e.getMessage());
                }

            }

            private List<AssemblyContext> getComponentHierarchy(AssemblyContext context) {
                var contextStack = new ArrayList<AssemblyContext>();

                while (context.getParentStructure__AssemblyContext() instanceof AssemblyContext) {
                    context = (AssemblyContext) context.getParentStructure__AssemblyContext();
                    contextStack.add(context);
                }
                return contextStack;
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
