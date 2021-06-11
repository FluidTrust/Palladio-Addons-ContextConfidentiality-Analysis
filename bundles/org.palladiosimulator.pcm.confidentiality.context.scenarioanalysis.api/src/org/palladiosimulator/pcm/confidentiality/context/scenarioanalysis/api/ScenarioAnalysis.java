package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api;

import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.api.ContextAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;

public interface ScenarioAnalysis extends ContextAnalysis {
    AnalysisResults runScenarioAnalysis(PCMBlackBoard pcm, ConfidentialAccessSpecification context, Configuration configuration);

}
