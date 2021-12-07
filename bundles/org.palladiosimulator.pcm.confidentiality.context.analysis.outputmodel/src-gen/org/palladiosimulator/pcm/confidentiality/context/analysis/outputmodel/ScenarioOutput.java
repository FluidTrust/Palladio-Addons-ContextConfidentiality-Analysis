/**
 */
package org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel;

import org.eclipse.emf.cdo.CDOObject;

import org.eclipse.emf.common.util.EList;

import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;

import org.palladiosimulator.pcm.core.composition.Connector;

import org.palladiosimulator.pcm.repository.OperationInterface;
import org.palladiosimulator.pcm.repository.OperationSignature;

import org.palladiosimulator.pcm.usagemodel.UsageScenario;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Scenario Output</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getScenario <em>Scenario</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getOperationsignature <em>Operationsignature</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getOperationinterface <em>Operationinterface</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getConnector <em>Connector</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getDecision <em>Decision</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getPolicyIDs <em>Policy IDs</em>}</li>
 * </ul>
 *
 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput()
 * @model
 * @extends CDOObject
 * @generated
 */
public interface ScenarioOutput extends CDOObject
{
	/**
	 * Returns the value of the '<em><b>Scenario</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Scenario</em>' reference.
	 * @see #setScenario(UsageScenario)
	 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput_Scenario()
	 * @model
	 * @generated
	 */
	UsageScenario getScenario();

	/**
	 * Sets the value of the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getScenario <em>Scenario</em>}' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @param value the new value of the '<em>Scenario</em>' reference.
	 * @see #getScenario()
	 * @generated
	 */
	void setScenario(UsageScenario value);

	/**
	 * Returns the value of the '<em><b>Operationsignature</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Operationsignature</em>' reference.
	 * @see #setOperationsignature(OperationSignature)
	 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput_Operationsignature()
	 * @model
	 * @generated
	 */
	OperationSignature getOperationsignature();

	/**
	 * Sets the value of the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getOperationsignature <em>Operationsignature</em>}' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @param value the new value of the '<em>Operationsignature</em>' reference.
	 * @see #getOperationsignature()
	 * @generated
	 */
	void setOperationsignature(OperationSignature value);

	/**
	 * Returns the value of the '<em><b>Operationinterface</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Operationinterface</em>' reference.
	 * @see #setOperationinterface(OperationInterface)
	 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput_Operationinterface()
	 * @model
	 * @generated
	 */
	OperationInterface getOperationinterface();

	/**
	 * Sets the value of the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getOperationinterface <em>Operationinterface</em>}' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @param value the new value of the '<em>Operationinterface</em>' reference.
	 * @see #getOperationinterface()
	 * @generated
	 */
	void setOperationinterface(OperationInterface value);

	/**
	 * Returns the value of the '<em><b>Connector</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Connector</em>' reference.
	 * @see #setConnector(Connector)
	 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput_Connector()
	 * @model
	 * @generated
	 */
	Connector getConnector();

	/**
	 * Sets the value of the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getConnector <em>Connector</em>}' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @param value the new value of the '<em>Connector</em>' reference.
	 * @see #getConnector()
	 * @generated
	 */
	void setConnector(Connector value);

	/**
	 * Returns the value of the '<em><b>Decision</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Decision</em>' attribute.
	 * @see #setDecision(DecisionType)
	 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput_Decision()
	 * @model dataType="org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.Result" required="true"
	 * @generated
	 */
	DecisionType getDecision();

	/**
	 * Sets the value of the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getDecision <em>Decision</em>}' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @param value the new value of the '<em>Decision</em>' attribute.
	 * @see #getDecision()
	 * @generated
	 */
	void setDecision(DecisionType value);

	/**
	 * Returns the value of the '<em><b>Policy IDs</b></em>' attribute list.
	 * The list contents are of type {@link java.lang.String}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Policy IDs</em>' attribute list.
	 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput_PolicyIDs()
	 * @model dataType="org.eclipse.emf.ecore.xml.type.String"
	 * @generated
	 */
	EList<String> getPolicyIDs();

} // ScenarioOutput
