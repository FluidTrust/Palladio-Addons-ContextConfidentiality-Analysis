package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelFactory;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.OperationInterface;
import org.palladiosimulator.pcm.repository.OperationSignature;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

import de.uka.ipd.sdq.identifier.Identifier;

public class ResultEMFModelStorage implements ScenarioResultStorage, FlipScenario {

    private final AnalysisResults results;

    public ResultEMFModelStorage() {
        this.results = OutputmodelFactory.eINSTANCE.createAnalysisResults();
    }

    @Override
    public void storeNegativeResult(final UsageScenario scenario, final OperationInterface operationInterface,
            final Signature signature, final Identifier connector, final PDPResult policies,
            final List<AssemblyContext> assembly) {

        // checking if positve result exists

        if (this.results.getScenariooutput().stream().filter(e -> EcoreUtil.equals(e.getScenario(), scenario))
                .anyMatch(e -> e.getDecision().equals(DecisionType.PERMIT))) {
            throw new IllegalStateException("Attempting to store a negative result for a positive scenario");
        }

        // checking for null values
        Objects.requireNonNull(scenario);
        // Objects.requireNonNull(operationInterface);
        Objects.requireNonNull(signature);
        Objects.requireNonNull(connector);
        Objects.requireNonNull(policies);

        final var scenarioResult = OutputmodelFactory.eINSTANCE.createScenarioOutput();

        // scenarioResult.setConnector(connector);
        // scenarioResult.setOperationsignature(signature);
        scenarioResult.setOperationinterface(operationInterface);
        scenarioResult.setScenario(scenario);
        scenarioResult.setDecision(policies.decision());
        scenarioResult.getPolicyIDs().addAll(policies.policyIdentifiers());
        scenarioResult.setOperationsignature((OperationSignature) signature);
        scenarioResult.getAssemblyContext().addAll(assembly);

        this.results.getScenariooutput().add(scenarioResult);

    }

    @Override
    public void storePositiveResult(final UsageScenario scenario, final PDPResult result) {
        Objects.requireNonNull(scenario);

        final var scenarioResult = OutputmodelFactory.eINSTANCE.createScenarioOutput();
        scenarioResult.setDecision(result.decision());
        scenarioResult.getPolicyIDs().addAll(result.policyIdentifiers());
        scenarioResult.setScenario(scenario);

        this.results.getScenariooutput().add(scenarioResult);

    }

    /**
     * Returns a a self-contained copy of the current internally used result model
     *
     * @return self-contained copy of the AnalysisResults
     */
    public AnalysisResults getResultModel() {
        return EcoreUtil.copy(this.results);
    }

    @Override
    public void flip(final UsageScenario scenario) {

        Objects.requireNonNull(scenario);
        final var outputScenario = this.results.getScenariooutput().stream()
                .filter(e -> EcoreUtil.equals(scenario, e.getScenario())).collect(Collectors.toList());
        if (outputScenario.isEmpty()) {
            throw new IllegalArgumentException("Usage scenario not found");
        }

        final var scenarioResult = OutputmodelFactory.eINSTANCE.createScenarioOutput();
        // scenarioResult.setResult(!outputScenario.get(0).isResult());
        scenarioResult.setScenario(scenario);

        this.results.getScenariooutput().removeAll(outputScenario);
        this.results.getScenariooutput().add(scenarioResult);
        throw new IllegalStateException("flip operation not implemented yet " + scenario);
    }

    @Override
    public void storePositiveResult(final UsageScenario scenario) {
        // TODO Auto-generated method stub
        final var scenarioResult = OutputmodelFactory.eINSTANCE.createScenarioOutput();
        scenarioResult.setDecision(DecisionType.PERMIT);
        scenarioResult.setScenario(scenario);

        this.results.getScenariooutput().add(scenarioResult);
    }

}
