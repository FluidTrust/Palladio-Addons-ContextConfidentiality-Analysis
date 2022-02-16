/**
 */
package org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel;

import org.eclipse.emf.ecore.EFactory;

/**
 * <!-- begin-user-doc -->
 * The <b>Factory</b> for the model.
 * It provides a create method for each non-abstract class of the model.
 * <!-- end-user-doc -->
 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage
 * @generated
 */
public interface OutputmodelFactory extends EFactory
{
	/**
	 * The singleton instance of the factory.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	OutputmodelFactory eINSTANCE = org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.OutputmodelFactoryImpl.init();

	/**
	 * Returns a new object of class '<em>Scenario Output</em>'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return a new object of class '<em>Scenario Output</em>'.
	 * @generated
	 */
	ScenarioOutput createScenarioOutput();

	/**
	 * Returns a new object of class '<em>Analysis Results</em>'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return a new object of class '<em>Analysis Results</em>'.
	 * @generated
	 */
	AnalysisResults createAnalysisResults();

	/**
	 * Returns the package supported by this factory.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the package supported by this factory.
	 * @generated
	 */
	OutputmodelPackage getOutputmodelPackage();

} //OutputmodelFactory
