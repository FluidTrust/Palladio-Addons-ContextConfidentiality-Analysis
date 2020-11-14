package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.emf.common.util.EList;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelFactory;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.ScenarioAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors.SeffAssemblyContext;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors.UsageModelVisitorScenarioSystem;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ServiceEffectSpecification;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;
import org.palladiosimulator.solver.transformations.PCMInstanceHelper;

public class ScenarioAnalysisSystemImpl implements ScenarioAnalysis {

    @Override
    public AnalysisResults runScenarioAnalysis(PCMBlackBoard pcm, ConfidentialAccessSpecification context) {

        var usage = pcm.getUsageModel();
        var result = OutputmodelFactory.eINSTANCE.createAnalysisResults();
        for (var scenario : usage.getUsageScenario_UsageModel()) {
            var visitor = new UsageModelVisitorScenarioSystem();
            var systemCalls = visitor.doSwitch(scenario.getScenarioBehaviour_UsageScenario());

            for (var systemCall : systemCalls) {
                
                var seff = getSEFF(systemCall,pcm);
                var visitor2 = new SeffAssemblyContext();
                var externalCallActions = visitor2.doSwitch(seff);
                var encapsulatingContexts = new ArrayList<AssemblyContext>();
                for (var externalAction :externalCallActions) {
                    var service = PCMInstanceHelper.getHandlingAssemblyContexts(externalAction, encapsulatingContexts);
                }
            }

            var output = OutputmodelFactory.eINSTANCE.createScenarioOutput();
//            output.setResult(analysisScenario(scenario, seffs, context));
            output.setScenario(scenario);
            result.getScenariooutput().add(output);
        }

        return result;

    }

    private ServiceEffectSpecification getSEFF(EntryLevelSystemCall call, PCMBlackBoard pcm) {
        Signature sig = call.getOperationSignature__EntryLevelSystemCall();

        List<AssemblyContext> acList = PCMInstanceHelper.getHandlingAssemblyContexts(call, pcm.getSystem());

        AssemblyContext ac = acList.get(acList.size() - 1);
        return getSEFF(sig, ac);
    }

    private ServiceEffectSpecification getSEFF(Signature sig, AssemblyContext ac) {
        BasicComponent bc = (BasicComponent) ac.getEncapsulatedComponent__AssemblyContext();
        EList<ServiceEffectSpecification> seffList = bc.getServiceEffectSpecifications__BasicComponent();
        for (ServiceEffectSpecification seff : seffList) {
            if (seff.getDescribedService__SEFF().getEntityName().equals(sig.getEntityName())) {
                return seff;
            }
        }
        return null;
    }

}
