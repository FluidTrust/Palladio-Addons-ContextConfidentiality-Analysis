/**
 */
package org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel;

import org.eclipse.emf.cdo.CDOObject;

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

} // ScenarioOutput
