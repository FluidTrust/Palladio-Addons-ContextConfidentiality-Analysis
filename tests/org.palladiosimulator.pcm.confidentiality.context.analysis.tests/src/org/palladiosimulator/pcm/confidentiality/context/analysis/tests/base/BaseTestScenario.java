package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.eclipse.emf.ecore.resource.Resource;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testframework.BaseTest;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.ScenarioAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.system.SystemFactory;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.DataTypes;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemcontextFactory;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.XACMLGenerator;
import org.palladiosimulator.pcm.repository.Repository;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.UsageModel;

public abstract class BaseTestScenario extends BaseTest {

    protected Repository repo;
    protected UsageModel usage;
    protected System assembly;
    protected ConfidentialAccessSpecification context;
    protected PCMBlackBoard blackBoard;
    protected ScenarioAnalysis analysis;
    protected Configuration configuration;

    // protected abstract void initLocal();

    @Override
    protected void assignValues(final List<Resource> list) {
        this.assembly = this.getModel(list, System.class);
        this.repo = this.getModel(list, Repository.class);
        this.context = this.getModel(list, ConfidentialAccessSpecification.class);
        this.usage = this.getModel(list, UsageModel.class);
    }

    @Override
    protected void generateXML() {
        final var generator = new XACMLGenerator();
        final var blackboard = new org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.PCMBlackBoard(
                this.assembly, null, null);
        generator.generateXACML(blackboard, this.context, this.pathXACML);
    }

    protected void assertAllPositive(final AnalysisResults output) {
        assertNotNull(output.getScenariooutput());

        for (final var scenario : output.getScenariooutput()) {
            assertTrue(scenario.isPassed());
        }
    }

    // protected ContextAttribute getContextAttributeByName(final String name) {
    // final var contextAttribute = this.context.getAttributes()
    //
    //
    // getContextContainer().stream().flatMap(e -> e.getContext().stream())
    // .filter(e -> name.equals(e.getEntityName())).findAny();
    // if (contextAttribute.isEmpty()) {
    // fail("ContextAttribute with name " + name + " not found");
    // }
    // return contextAttribute.get();
    // }
    //
    // protected ContextSpecification getSpecificationByName(final String name) {
    // final var specification =
    // this.context.getPcmspecificationcontainer().getContextspecification().stream()
    // .filter(e -> name.equals(e.getEntityName())).findAny();
    // if (specification.isEmpty()) {
    // fail("Specification with name " + name + " not found");
    // }
    // return specification.get();
    // }
    //
    // protected SystemPolicySpecification getPolicySpecificationByName(final String name) {
    // final var policySpecification =
    // this.context.getPcmspecificationcontainer().getPolicyspecification().stream()
    // .filter(e -> name.equals(e.getEntityName())).findAny();
    // if (policySpecification.isEmpty()) {
    // fail("Policy with name " + name + " not found");
    // }
    // return policySpecification.get();
    // }
    //
    // protected DecisionType getScenarioResultByName(final AnalysisResults results, final String
    // name) {
    // final var scenario = getScenarioByName(results, name);
    // return scenario.getDecision();
    // }
    //
    // protected List<ScenarioOutput> getScenariosByName(final AnalysisResults results, final String
    // name) {
    // return results.getScenariooutput().stream().filter(e ->
    // e.getScenario().getEntityName().equals(name))
    // .collect(Collectors.toList());
    // }
    //
    // protected ScenarioOutput getScenarioByName(final AnalysisResults results, final String name)
    // {
    // final var output = results.getScenariooutput().stream()
    // .filter(e -> e.getScenario().getEntityName().equals(name)).findAny();
    // if (output.isEmpty()) {
    // fail("Scenario with name " + name + " not found");
    // }
    // return output.get();
    // }
    //
    // protected void clearContextSetByName(final String name) {
    // final var set = getPolicyByName(name);
    // set.getRule().clear();
    // }
    //
    // protected Policy getPolicyByName(final String name) {
    // final var set = this.context.getPolicyset().getPolicy().stream().filter(e ->
    // name.equals(e.getEntityName()))
    // .findAny();
    // if (set.isEmpty()) {
    // fail("Contextset with name " + name + " not found");
    // }
    // return set.get();
    // }
    //
    // protected ContextAttribute createSingleContext(final String name) {
    // final var context = ModelFactory.eINSTANCE.createSingleAttributeContext();
    // context.setEntityName(name);
    // return context;
    // }
    //
    // protected HierarchicalContext createHierarchicalContext(final String name) {
    // final var context = ModelFactory.eINSTANCE.createHierarchicalContext();
    // context.setEntityName(name);
    // return context;
    // }
    //
    // protected RelatedContextSet createRelatedContext(final String name) {
    // final var context = ModelFactory.eINSTANCE.createRelatedContextSet();
    // context.setEntityName(name);
    // return context;
    //
    // }

    protected UsageSpecification createContext(final String name) {
        final var contextAccess = SystemFactory.eINSTANCE.createUsageSpecification();

        final var attribute = SystemcontextFactory.eINSTANCE.createSimpleAttribute();
        final var attributeValue = SystemcontextFactory.eINSTANCE.createAttributeValue();
        attributeValue.getValues()
            .add(name);
        attributeValue.setType(DataTypes.STRING);
        attribute.getAttributevalue()
            .add(attributeValue);

        contextAccess.setEntityName(name);
        contextAccess.setAttribute(attribute);
        contextAccess.setAttributevalue(attributeValue);
        this.context.getAttributes()
            .getAttribute()
            .add(attribute);
        this.context.getPcmspecificationcontainer()
            .getUsagespecification()
            .add(contextAccess);
        return contextAccess;
    }

}
