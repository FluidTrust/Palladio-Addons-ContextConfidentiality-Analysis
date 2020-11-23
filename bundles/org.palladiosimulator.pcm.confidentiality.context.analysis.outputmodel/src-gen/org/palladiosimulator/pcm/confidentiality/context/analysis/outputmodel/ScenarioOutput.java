/**
 */
package org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel;

import org.eclipse.emf.cdo.CDOObject;

import org.eclipse.emf.common.util.EList;
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
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#isResult <em>Result</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getScenario <em>Scenario</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getOperationsignature <em>Operationsignature</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getOperationinterface <em>Operationinterface</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getConnector <em>Connector</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getRequestorSet <em>Requestor Set</em>}</li>
 *   <li>{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getRequiredSets <em>Required Sets</em>}</li>
 * </ul>
 *
 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput()
 * @model
 * @extends CDOObject
 * @generated
 */
public interface ScenarioOutput extends CDOObject {
    /**
     * Returns the value of the '<em><b>Result</b></em>' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the value of the '<em>Result</em>' attribute.
     * @see #setResult(boolean)
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput_Result()
     * @model
     * @generated
     */
    boolean isResult();

    /**
     * Sets the value of the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#isResult <em>Result</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @param value the new value of the '<em>Result</em>' attribute.
     * @see #isResult()
     * @generated
     */
    void setResult(boolean value);

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
     * Returns the value of the '<em><b>Requestor Set</b></em>' reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the value of the '<em>Requestor Set</em>' reference.
     * @see #setRequestorSet(org.palladiosimulator.pcm.confidentiality.context.set.ContextSet)
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput_RequestorSet()
     * @model
     * @generated
     */
    org.palladiosimulator.pcm.confidentiality.context.set.ContextSet getRequestorSet();

    /**
     * Sets the value of the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getRequestorSet <em>Requestor Set</em>}' reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @param value the new value of the '<em>Requestor Set</em>' reference.
     * @see #getRequestorSet()
     * @generated
     */
    void setRequestorSet(org.palladiosimulator.pcm.confidentiality.context.set.ContextSet value);

    /**
     * Returns the value of the '<em><b>Required Sets</b></em>' reference list.
     * The list contents are of type {@link org.palladiosimulator.pcm.confidentiality.context.set.ContextSet}.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the value of the '<em>Required Sets</em>' reference list.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage#getScenarioOutput_RequiredSets()
     * @model
     * @generated
     */
    EList<org.palladiosimulator.pcm.confidentiality.context.set.ContextSet> getRequiredSets();

} // ScenarioOutput
