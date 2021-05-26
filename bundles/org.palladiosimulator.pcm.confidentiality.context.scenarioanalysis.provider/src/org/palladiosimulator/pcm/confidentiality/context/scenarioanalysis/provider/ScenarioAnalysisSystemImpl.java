package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider;

import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.ScenarioAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation.ResultEMFModelStorage;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors.CheckOperation;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors.SystemWalker;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors.UsageModelVisitorScenarioSystem;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.set.SetFactory;
import org.palladiosimulator.pcm.confidentiality.context.specification.ContextSpecification;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

public class ScenarioAnalysisSystemImpl implements ScenarioAnalysis {

    @Override
    public AnalysisResults runScenarioAnalysis(PCMBlackBoard pcm, ConfidentialAccessSpecification context) {

        var usage = pcm.getUsageModel();
        var result = new ResultEMFModelStorage();

        for (var scenario : usage.getUsageScenario_UsageModel()) {
            var requestor = this.getRequestorContexts(context, scenario);

            var visitor = new UsageModelVisitorScenarioSystem();
            var systemCalls = visitor.doSwitch(scenario.getScenarioBehaviour_UsageScenario());

            for (var systemCall : systemCalls) {
                var tmpRequestor = getRequestorContexts(context, systemCall, requestor);
                var checkOperation = new CheckOperation(pcm, context, result, scenario);
                var walker = new SystemWalker(checkOperation);
                walker.propagationBySeff(systemCall, pcm.getSystem(), tmpRequestor);
            }

            // set positiv return value if no error happened
            if (result.getResultModel().getScenariooutput().stream()
                    .noneMatch(e -> EcoreUtil.equals(e.getScenario(), scenario))) {
                result.storePositiveResult(scenario);
            }
            if(isMisusage(context, scenario)) {
                result.flip(scenario);
            }

        }

        return result.getResultModel();

    }

    private ContextSet getRequestorContexts(ConfidentialAccessSpecification access, UsageScenario scenario) {
        var requestorStream = getSpecificationScenario(access, scenario);
        var requestor = requestorStream.map(ContextSpecification::getContextset).findAny();
        return requestor.orElse(SetFactory.eINSTANCE.createContextSet());
    }
    
    private boolean isMisusage(ConfidentialAccessSpecification access, UsageScenario scenario) {
        var scenarioSpecification = getSpecificationScenario(access, scenario).findAny();
        if(scenarioSpecification.isPresent())
            return scenarioSpecification.get().isMissageUse();
        return false;
    }

    private Stream<ContextSpecification> getSpecificationScenario(ConfidentialAccessSpecification access,
            UsageScenario scenario) {
        return access.getPcmspecificationcontainer().getContextspecification().stream()
                .filter(e -> EcoreUtil.equals(e.getUsagescenario(), scenario));
    }

    private ContextSet getRequestorContexts(ConfidentialAccessSpecification access, EntryLevelSystemCall systemCall,
            ContextSet oldSet) {
        var requestor = access.getPcmspecificationcontainer().getContextspecification().stream()
                .filter(e -> EcoreUtil.equals(e.getEntrylevelsystemcall(), systemCall))
                .map(ContextSpecification::getContextset).findAny();
        return requestor.orElse(oldSet);
    }

}
