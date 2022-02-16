/**
 */
package org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel;

import org.eclipse.emf.cdo.CDOObject;

import org.eclipse.emf.common.util.EList;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Analysis Results</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults#getScenariooutput <em>Scenariooutput</em>}</li>
 * </ul>
 *
 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getAnalysisResults()
 * @model
 * @extends CDOObject
 * @generated
 */
public interface AnalysisResults extends CDOObject
{
	/**
	 * Returns the value of the '<em><b>Scenariooutput</b></em>' containment reference list.
	 * The list contents are of type {@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Scenariooutput</em>' containment reference list.
	 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getAnalysisResults_Scenariooutput()
	 * @model containment="true"
	 * @generated
	 */
	EList<ScenarioOutput> getScenariooutput();

} // AnalysisResults
