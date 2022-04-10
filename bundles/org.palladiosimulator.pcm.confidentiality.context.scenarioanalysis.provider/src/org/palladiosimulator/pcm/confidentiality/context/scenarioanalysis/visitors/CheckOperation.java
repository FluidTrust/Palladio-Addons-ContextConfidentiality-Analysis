package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.helper.PolicyHelper;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation.ScenarioResultStorage;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.Evaluate;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.Connector;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ExternalCallAction;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

import de.uka.ipd.sdq.identifier.Identifier;

public class CheckOperation {

    private final ScenarioResultStorage storage;
    private final UsageScenario scenario;
    private final Configuration configuration;
    private final Evaluate eval;

    public CheckOperation(final PCMBlackBoard pcm, final ConfidentialAccessSpecification accessSpecification,
            final ScenarioResultStorage storage, final UsageScenario scenario, final Configuration configuration,
            final Evaluate eval) {
        // non null checks
        Objects.requireNonNull(pcm);
        Objects.requireNonNull(accessSpecification);
        Objects.requireNonNull(storage);
        Objects.requireNonNull(scenario);
        Objects.requireNonNull(configuration);
        Objects.requireNonNull(eval);

        this.storage = storage;
        this.scenario = scenario;
        this.configuration = configuration;
        this.eval = eval;
    }

    public void performCheck(final Signature signature, Connector connector,
            final Deque<AssemblyContext> component, final ResourceDemandingSEFF seff,
            final List<? extends UsageSpecification> requestorContext, ServiceSpecification originService,
            ExternalCallAction originAction) {

        performCheckEntity(signature, connector, component, seff, requestorContext, originService, originAction);
    }

    public void performCheckEntity(final Signature signature, Connector connector,
            final Deque<AssemblyContext> component, final Identifier seff,
            final List<? extends UsageSpecification> requestorContext, ServiceSpecification originService,
            ExternalCallAction originAction) {
        final var listSubject = new ArrayList<UsageSpecification>();
        final var listEnvironment = new ArrayList<UsageSpecification>();
        final var listResource = new ArrayList<UsageSpecification>();
        final var listAction = new ArrayList<UsageSpecification>();
        final var listXML = new ArrayList<UsageSpecification>();

        PolicyHelper.createRequestAttributes(signature, component, requestorContext, listSubject, listEnvironment,
                listResource, listAction, listXML);

        final var resultOpt = this.eval.evaluate(listSubject, listEnvironment, listResource, listAction, listXML);

        if (resultOpt.isEmpty()) {
            throw new IllegalStateException("Empty PDP-Results");
        }
        final var result = resultOpt.get();

        this.storage.storeResult(this.scenario, signature, seff, connector, result, new LinkedList<>(component),
                originService, originAction);

    }

}
