/**
 */
package org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EDataType;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.EPackage;

import org.eclipse.emf.ecore.impl.EFactoryImpl;

import org.eclipse.emf.ecore.plugin.EcorePlugin;

import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.*;

import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model <b>Factory</b>.
 * <!-- end-user-doc -->
 * @generated
 */
public class OutputmodelFactoryImpl extends EFactoryImpl implements OutputmodelFactory
{
	/**
	 * Creates the default factory implementation.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public static OutputmodelFactory init()
	{
		try
		{
			OutputmodelFactory theOutputmodelFactory = (OutputmodelFactory)EPackage.Registry.INSTANCE.getEFactory(OutputmodelPackage.eNS_URI);
			if (theOutputmodelFactory != null)
			{
				return theOutputmodelFactory;
			}
		}
		catch (Exception exception)
		{
			EcorePlugin.INSTANCE.log(exception);
		}
		return new OutputmodelFactoryImpl();
	}

	/**
	 * Creates an instance of the factory.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public OutputmodelFactoryImpl()
	{
		super();
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public EObject create(EClass eClass)
	{
		switch (eClass.getClassifierID())
		{
			case OutputmodelPackage.SCENARIO_OUTPUT: return (EObject)createScenarioOutput();
			case OutputmodelPackage.ANALYSIS_RESULTS: return (EObject)createAnalysisResults();
			default:
				throw new IllegalArgumentException("The class '" + eClass.getName() + "' is not a valid classifier");
		}
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public Object createFromString(EDataType eDataType, String initialValue)
	{
		switch (eDataType.getClassifierID())
		{
			case OutputmodelPackage.RESULT:
				return createResultFromString(eDataType, initialValue);
			default:
				throw new IllegalArgumentException("The datatype '" + eDataType.getName() + "' is not a valid classifier");
		}
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public String convertToString(EDataType eDataType, Object instanceValue)
	{
		switch (eDataType.getClassifierID())
		{
			case OutputmodelPackage.RESULT:
				return convertResultToString(eDataType, instanceValue);
			default:
				throw new IllegalArgumentException("The datatype '" + eDataType.getName() + "' is not a valid classifier");
		}
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public ScenarioOutput createScenarioOutput()
	{
		ScenarioOutputImpl scenarioOutput = new ScenarioOutputImpl();
		return scenarioOutput;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public AnalysisResults createAnalysisResults()
	{
		AnalysisResultsImpl analysisResults = new AnalysisResultsImpl();
		return analysisResults;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public DecisionType createResultFromString(EDataType eDataType, String initialValue)
	{
		return (DecisionType)super.createFromString(eDataType, initialValue);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public String convertResultToString(EDataType eDataType, Object instanceValue)
	{
		return super.convertToString(eDataType, instanceValue);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public OutputmodelPackage getOutputmodelPackage()
	{
		return (OutputmodelPackage)getEPackage();
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @deprecated
	 * @generated
	 */
	@Deprecated
	public static OutputmodelPackage getPackage()
	{
		return OutputmodelPackage.eINSTANCE;
	}

} //OutputmodelFactoryImpl
