/**
 */
package org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;

import org.eclipse.emf.internal.cdo.CDOObjectImpl;

import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Analysis Results</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.AnalysisResultsImpl#getScenariooutput <em>Scenariooutput</em>}</li>
 * </ul>
 *
 * @generated
 */
public class AnalysisResultsImpl extends CDOObjectImpl implements AnalysisResults
{
	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected AnalysisResultsImpl()
	{
		super();
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	protected EClass eStaticClass()
	{
		return OutputmodelPackage.Literals.ANALYSIS_RESULTS;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	protected int eStaticFeatureCount()
	{
		return 0;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@SuppressWarnings("unchecked")
	public EList<ScenarioOutput> getScenariooutput()
	{
		return (EList<ScenarioOutput>)eGet(OutputmodelPackage.Literals.ANALYSIS_RESULTS__SCENARIOOUTPUT, true);
	}

} //AnalysisResultsImpl
