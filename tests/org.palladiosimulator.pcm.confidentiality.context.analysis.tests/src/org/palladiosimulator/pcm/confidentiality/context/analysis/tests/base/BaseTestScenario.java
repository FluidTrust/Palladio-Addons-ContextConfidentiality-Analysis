package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base;

import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.resource.Resource;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testframework.BaseTest;
import org.palladiosimulator.pcm.confidentiality.context.model.ContextAttribute;
import org.palladiosimulator.pcm.confidentiality.context.model.HierarchicalContext;
import org.palladiosimulator.pcm.confidentiality.context.model.ModelFactory;
import org.palladiosimulator.pcm.confidentiality.context.model.RelatedContextSet;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.specification.ContextSpecification;
import org.palladiosimulator.pcm.repository.Repository;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.UsageModel;

public abstract class BaseTestScenario extends BaseTest {

    private static final String PATH_ASSEMBLY = "travelplanner/default.system";
    private static final String PATH_REPOSITORY = "travelplanner/default.repository";
    private static final String PATH_USAGE = "travelplanner/default.usagemodel";
    private static final String PATH_CONTEXT = "travelplanner/Scenarios/test_model_02.context";
    protected Repository repo;
    protected UsageModel usage;
    protected System assembly;
    protected ConfidentialAccessSpecification context;

    @Override
    protected List<String> getModelsPath() {
        final var list = new ArrayList<String>();

        list.add(PATH_USAGE);
        list.add(PATH_ASSEMBLY);
        list.add(PATH_REPOSITORY);
        list.add(PATH_CONTEXT);

        return list;
    }

    @Override
    protected void assignValues(final List<Resource> list) {
        this.assembly = this.getModel(list, System.class);
        this.repo = this.getModel(list, Repository.class);
        this.context = this.getModel(list, ConfidentialAccessSpecification.class);
        this.usage = this.getModel(list, UsageModel.class);
    }

    protected ContextAttribute getContextAttributeByName(final String name) {
        final var contextAttribute = this.context.getContextContainer().stream().flatMap(e -> e.getContext().stream())
                .filter(e -> name.equals(e.getEntityName())).findAny();
        if (contextAttribute.isEmpty()) {
            fail("ContextAttribute with name " + name + " not found");
        }
        return contextAttribute.get();
    }

    protected ContextSpecification getSpecificationByName(final String name) {
        final var specification = this.context.getPcmspecificationcontainer().getContextspecification().stream()
                .filter(e -> name.equals(e.getEntityName())).findAny();
        if (specification.isEmpty()) {
            fail("Specification with name " + name + " not found");
        }
        return specification.get();
    }

    protected boolean getScenarioResultByName(final AnalysisResults results, final String name) {
        final var scenario = this.getScenarioByName(results, name);
        return scenario.isResult();
    }

    protected List<ScenarioOutput> getScenariosByName(final AnalysisResults results, final String name) {
        return results.getScenariooutput().stream().filter(e -> e.getScenario().getEntityName().equals(name))
                .collect(Collectors.toList());
    }

    protected ScenarioOutput getScenarioByName(final AnalysisResults results, final String name) {
        final var output = results.getScenariooutput().stream()
                .filter(e -> e.getScenario().getEntityName().equals(name)).findAny();
        if (output.isEmpty()) {
            fail("Scenario with name " + name + " not found");
        }
        return output.get();
    }

    protected void clearContextSetByName(final String name) {
        final var set = this.getContextSetByName(name);
        set.getContexts().clear();
    }

    protected ContextSet getContextSetByName(final String name) {
        final var set = this.context.getSetContainer().stream().flatMap(e -> e.getPolicies().stream())
                .filter(e -> name.equals(e.getEntityName())).findAny();
        if (set.isEmpty()) {
            fail("Contextset with name " + name + " not found");
        }
        return set.get();
    }

    protected ContextAttribute createSingleContext(final String name) {
        final var context = ModelFactory.eINSTANCE.createSingleAttributeContext();
        context.setEntityName(name);
        return context;
    }

    protected HierarchicalContext createHierarchicalContext(final String name) {
        final var context = ModelFactory.eINSTANCE.createHierarchicalContext();
        context.setEntityName(name);
        return context;
    }

    protected RelatedContextSet createRelatedContext(final String name) {
        final var context = ModelFactory.eINSTANCE.createRelatedContextSet();
        context.setEntityName(name);
        return context;

    }

}
