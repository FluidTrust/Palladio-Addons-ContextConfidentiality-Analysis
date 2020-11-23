package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation;

import java.util.List;
import java.util.Objects;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelFactory;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.core.composition.Connector;
import org.palladiosimulator.pcm.repository.OperationInterface;
import org.palladiosimulator.pcm.repository.OperationSignature;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

public class ResultEMFModelStorage implements ScenarioResultStorage {

    private AnalysisResults results;

    public ResultEMFModelStorage() {
        results = OutputmodelFactory.eINSTANCE.createAnalysisResults();
        ;
    }

    @Override
    public void storeNegativeResult(UsageScenario scenario, OperationInterface operationInterface,
            OperationSignature signature, Connector connector, ContextSet requestor, List<ContextSet> policies) {

        // checking if positve result exists
        if (results.getScenariooutput().stream().filter(e -> EcoreUtil.equals(e.getScenario(), scenario))
                .anyMatch(ScenarioOutput::isResult))
            throw new IllegalStateException("Attempting to store a negative result for a positive scenario");
        
        // checking for null values
        Objects.requireNonNull(scenario);
        Objects.requireNonNull(operationInterface);
        Objects.requireNonNull(signature);
        Objects.requireNonNull(connector);
        Objects.requireNonNull(requestor);
        Objects.requireNonNull(policies);

        var scenarioResult = OutputmodelFactory.eINSTANCE.createScenarioOutput();
        scenarioResult.setResult(false);
        scenarioResult.setConnector(connector);
        scenarioResult.setOperationsignature(signature);
        scenarioResult.setOperationinterface(operationInterface);
        scenarioResult.setRequestorSet(requestor);
        scenarioResult.setScenario(scenario);
        scenarioResult.getRequiredSets().addAll(policies);
        
        results.getScenariooutput().add(scenarioResult);

    }

    @Override
    public void storePositiveResult(UsageScenario scenario) {
        //checking for negative results
        if (results.getScenariooutput().stream().filter(e -> EcoreUtil.equals(e.getScenario(), scenario))
                .anyMatch(ScenarioOutput::isResult))
            throw new IllegalStateException("Attempting to store a negative result for a positive scenario");
        
        Objects.requireNonNull(scenario);
        
        var scenarioResult = OutputmodelFactory.eINSTANCE.createScenarioOutput();
        scenarioResult.setResult(true);
        scenarioResult.setScenario(scenario);
        
        results.getScenariooutput().add(scenarioResult);

    }
    
    /**
     * Returns a a self-contained copy of the current internally used result model
     * @return self-contained copy of the AnalysisResults
     */
    public AnalysisResults getResultModel() {
        return EcoreUtil.copy(results);
    }

}
