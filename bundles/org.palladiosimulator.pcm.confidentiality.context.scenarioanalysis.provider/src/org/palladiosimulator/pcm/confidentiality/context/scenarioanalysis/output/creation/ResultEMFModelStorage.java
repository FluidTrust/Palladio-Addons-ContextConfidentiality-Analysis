package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelFactory;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.Connector;
import org.palladiosimulator.pcm.repository.OperationSignature;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ExternalCallAction;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

import de.uka.ipd.sdq.identifier.Identifier;

public final class ResultEMFModelStorage implements ScenarioResultStorage {

    private final Map<String, ScenarioOutput> resultMap;

    public ResultEMFModelStorage() {
        this.resultMap = new HashMap<>();
    }

    public void addScenario(final UsageScenario scenario, final boolean misusage) {

        if (this.resultMap.containsKey(scenario.getId())) {
            throw new IllegalStateException("ScenarioOutput for scenario already exists");
        }
        final var outputScenario = OutputmodelFactory.eINSTANCE.createScenarioOutput();
        outputScenario.setScenario(scenario);
        outputScenario.setMisUsage(misusage);
        this.resultMap.put(scenario.getId(), outputScenario);

    }

    @Override
    public void storeResult(final UsageScenario scenario, final Signature signature, final Identifier seff,
            final Connector connector, final PDPResult policies, final List<AssemblyContext> assembly,
            final ServiceSpecification originService, final ExternalCallAction originAction) {

        // checking for null values
        Objects.requireNonNull(scenario);
        Objects.requireNonNull(signature);
        Objects.requireNonNull(seff);
        Objects.requireNonNull(policies);

        if (!this.resultMap.containsKey(scenario.getId())) {
            throw new IllegalStateException("Result storage before scenario initialisation");
        }

        final var output = this.resultMap.get(scenario.getId());

        final var scenarioResult = OutputmodelFactory.eINSTANCE.createOperationOutput();

        scenarioResult.setDecision(policies.decision());
        scenarioResult.getPolicyIDs()
            .addAll(policies.policyIdentifiers());
        scenarioResult.setOperationsignature((OperationSignature) signature);
        scenarioResult.getAssemblyContext()
            .addAll(assembly);
        scenarioResult.setConnector(connector);
        scenarioResult.setOriginService(originService);
        scenarioResult.setOrgiginAction(originAction);

        output.getOperationOutput()
            .add(scenarioResult);

    }

    /**
     * Returns the current {@link AnalysisResults} model
     *
     * @return AnalysisResults
     */
    public AnalysisResults getResultModel() {
        final var results = OutputmodelFactory.eINSTANCE.createAnalysisResults();
        this.finishScenarios();
        results.getScenariooutput()
            .addAll(this.resultMap.values());

        return results;
    }

    /**
     * Decides for all scenarios whether they are passed or not
     */
    private void finishScenarios() {
        for (final var scenario : this.resultMap.values()) {
            if (!scenario.isMisUsage()) {
                if (scenario.getOperationOutput()
                    .stream()
                    .allMatch(e -> e.getDecision()
                        .equals(DecisionType.PERMIT))) {
                    scenario.setPassed(true);
                } else {
                    scenario.setPassed(false);
                }
            } else {
                if (scenario.getOperationOutput()
                    .stream()
                    .anyMatch(e -> e.getDecision()
                        .equals(DecisionType.DENY))) {
                    scenario.setPassed(true);
                } else {
                    scenario.setPassed(false);
                }
            }

        }
    }

}
