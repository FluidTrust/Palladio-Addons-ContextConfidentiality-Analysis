/**
 */
package org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel;

import org.eclipse.emf.ecore.EAttribute;
import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EPackage;
import org.eclipse.emf.ecore.EReference;

/**
 * <!-- begin-user-doc -->
 * The <b>Package</b> for the model.
 * It contains accessors for the meta objects to represent
 * <ul>
 *   <li>each class,</li>
 *   <li>each feature of each class,</li>
 *   <li>each operation of each class,</li>
 *   <li>each enum,</li>
 *   <li>and each data type</li>
 * </ul>
 * <!-- end-user-doc -->
 * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelFactory
 * @model kind="package"
 * @generated
 */
public interface OutputmodelPackage extends EPackage {
    /**
     * The package name.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    String eNAME = "outputmodel";

    /**
     * The package namespace URI.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    String eNS_URI = "http://www.palladiosimulator.org/pcm/confidentiality/scenario/0.1/";

    /**
     * The package namespace name.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    String eNS_PREFIX = "outputmodel";

    /**
     * The singleton instance of the package.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    OutputmodelPackage eINSTANCE = org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.OutputmodelPackageImpl
            .init();

    /**
     * The meta object id for the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.ScenarioOutputImpl <em>Scenario Output</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.ScenarioOutputImpl
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.OutputmodelPackageImpl#getScenarioOutput()
     * @generated
     */
    int SCENARIO_OUTPUT = 0;

    /**
     * The feature id for the '<em><b>Result</b></em>' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     * @ordered
     */
    int SCENARIO_OUTPUT__RESULT = 0;

    /**
     * The feature id for the '<em><b>Scenario</b></em>' reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     * @ordered
     */
    int SCENARIO_OUTPUT__SCENARIO = 1;

    /**
     * The feature id for the '<em><b>Operationsignature</b></em>' reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     * @ordered
     */
    int SCENARIO_OUTPUT__OPERATIONSIGNATURE = 2;

    /**
     * The feature id for the '<em><b>Operationinterface</b></em>' reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     * @ordered
     */
    int SCENARIO_OUTPUT__OPERATIONINTERFACE = 3;

    /**
     * The feature id for the '<em><b>Connector</b></em>' reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     * @ordered
     */
    int SCENARIO_OUTPUT__CONNECTOR = 4;

    /**
     * The feature id for the '<em><b>Requestor Set</b></em>' reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     * @ordered
     */
    int SCENARIO_OUTPUT__REQUESTOR_SET = 5;

    /**
     * The feature id for the '<em><b>Required Sets</b></em>' reference list.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     * @ordered
     */
    int SCENARIO_OUTPUT__REQUIRED_SETS = 6;

    /**
     * The number of structural features of the '<em>Scenario Output</em>' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     * @ordered
     */
    int SCENARIO_OUTPUT_FEATURE_COUNT = 7;

    /**
     * The meta object id for the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.AnalysisResultsImpl <em>Analysis Results</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.AnalysisResultsImpl
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.OutputmodelPackageImpl#getAnalysisResults()
     * @generated
     */
    int ANALYSIS_RESULTS = 1;

    /**
     * The feature id for the '<em><b>Scenariooutput</b></em>' containment reference list.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     * @ordered
     */
    int ANALYSIS_RESULTS__SCENARIOOUTPUT = 0;

    /**
     * The number of structural features of the '<em>Analysis Results</em>' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     * @ordered
     */
    int ANALYSIS_RESULTS_FEATURE_COUNT = 1;

    /**
     * Returns the meta object for class '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput <em>Scenario Output</em>}'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the meta object for class '<em>Scenario Output</em>'.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput
     * @generated
     */
    EClass getScenarioOutput();

    /**
     * Returns the meta object for the attribute '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#isResult <em>Result</em>}'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the meta object for the attribute '<em>Result</em>'.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#isResult()
     * @see #getScenarioOutput()
     * @generated
     */
    EAttribute getScenarioOutput_Result();

    /**
     * Returns the meta object for the reference '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getScenario <em>Scenario</em>}'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the meta object for the reference '<em>Scenario</em>'.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getScenario()
     * @see #getScenarioOutput()
     * @generated
     */
    EReference getScenarioOutput_Scenario();

    /**
     * Returns the meta object for the reference '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getOperationsignature <em>Operationsignature</em>}'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the meta object for the reference '<em>Operationsignature</em>'.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getOperationsignature()
     * @see #getScenarioOutput()
     * @generated
     */
    EReference getScenarioOutput_Operationsignature();

    /**
     * Returns the meta object for the reference '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getOperationinterface <em>Operationinterface</em>}'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the meta object for the reference '<em>Operationinterface</em>'.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getOperationinterface()
     * @see #getScenarioOutput()
     * @generated
     */
    EReference getScenarioOutput_Operationinterface();

    /**
     * Returns the meta object for the reference '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getConnector <em>Connector</em>}'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the meta object for the reference '<em>Connector</em>'.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getConnector()
     * @see #getScenarioOutput()
     * @generated
     */
    EReference getScenarioOutput_Connector();

    /**
     * Returns the meta object for the reference '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getRequestorSet <em>Requestor Set</em>}'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the meta object for the reference '<em>Requestor Set</em>'.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getRequestorSet()
     * @see #getScenarioOutput()
     * @generated
     */
    EReference getScenarioOutput_RequestorSet();

    /**
     * Returns the meta object for the reference list '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getRequiredSets <em>Required Sets</em>}'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the meta object for the reference list '<em>Required Sets</em>'.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput#getRequiredSets()
     * @see #getScenarioOutput()
     * @generated
     */
    EReference getScenarioOutput_RequiredSets();

    /**
     * Returns the meta object for class '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults <em>Analysis Results</em>}'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the meta object for class '<em>Analysis Results</em>'.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults
     * @generated
     */
    EClass getAnalysisResults();

    /**
     * Returns the meta object for the containment reference list '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults#getScenariooutput <em>Scenariooutput</em>}'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the meta object for the containment reference list '<em>Scenariooutput</em>'.
     * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults#getScenariooutput()
     * @see #getAnalysisResults()
     * @generated
     */
    EReference getAnalysisResults_Scenariooutput();

    /**
     * Returns the factory that creates the instances of the model.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the factory that creates the instances of the model.
     * @generated
     */
    OutputmodelFactory getOutputmodelFactory();

    /**
     * <!-- begin-user-doc -->
     * Defines literals for the meta objects that represent
     * <ul>
     *   <li>each class,</li>
     *   <li>each feature of each class,</li>
     *   <li>each operation of each class,</li>
     *   <li>each enum,</li>
     *   <li>and each data type</li>
     * </ul>
     * <!-- end-user-doc -->
     * @generated
     */
    interface Literals {
        /**
         * The meta object literal for the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.ScenarioOutputImpl <em>Scenario Output</em>}' class.
         * <!-- begin-user-doc -->
         * <!-- end-user-doc -->
         * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.ScenarioOutputImpl
         * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.OutputmodelPackageImpl#getScenarioOutput()
         * @generated
         */
        EClass SCENARIO_OUTPUT = eINSTANCE.getScenarioOutput();

        /**
         * The meta object literal for the '<em><b>Result</b></em>' attribute feature.
         * <!-- begin-user-doc -->
         * <!-- end-user-doc -->
         * @generated
         */
        EAttribute SCENARIO_OUTPUT__RESULT = eINSTANCE.getScenarioOutput_Result();

        /**
         * The meta object literal for the '<em><b>Scenario</b></em>' reference feature.
         * <!-- begin-user-doc -->
         * <!-- end-user-doc -->
         * @generated
         */
        EReference SCENARIO_OUTPUT__SCENARIO = eINSTANCE.getScenarioOutput_Scenario();

        /**
         * The meta object literal for the '<em><b>Operationsignature</b></em>' reference feature.
         * <!-- begin-user-doc -->
         * <!-- end-user-doc -->
         * @generated
         */
        EReference SCENARIO_OUTPUT__OPERATIONSIGNATURE = eINSTANCE.getScenarioOutput_Operationsignature();

        /**
         * The meta object literal for the '<em><b>Operationinterface</b></em>' reference feature.
         * <!-- begin-user-doc -->
         * <!-- end-user-doc -->
         * @generated
         */
        EReference SCENARIO_OUTPUT__OPERATIONINTERFACE = eINSTANCE.getScenarioOutput_Operationinterface();

        /**
         * The meta object literal for the '<em><b>Connector</b></em>' reference feature.
         * <!-- begin-user-doc -->
         * <!-- end-user-doc -->
         * @generated
         */
        EReference SCENARIO_OUTPUT__CONNECTOR = eINSTANCE.getScenarioOutput_Connector();

        /**
         * The meta object literal for the '<em><b>Requestor Set</b></em>' reference feature.
         * <!-- begin-user-doc -->
         * <!-- end-user-doc -->
         * @generated
         */
        EReference SCENARIO_OUTPUT__REQUESTOR_SET = eINSTANCE.getScenarioOutput_RequestorSet();

        /**
         * The meta object literal for the '<em><b>Required Sets</b></em>' reference list feature.
         * <!-- begin-user-doc -->
         * <!-- end-user-doc -->
         * @generated
         */
        EReference SCENARIO_OUTPUT__REQUIRED_SETS = eINSTANCE.getScenarioOutput_RequiredSets();

        /**
         * The meta object literal for the '{@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.AnalysisResultsImpl <em>Analysis Results</em>}' class.
         * <!-- begin-user-doc -->
         * <!-- end-user-doc -->
         * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.AnalysisResultsImpl
         * @see org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.impl.OutputmodelPackageImpl#getAnalysisResults()
         * @generated
         */
        EClass ANALYSIS_RESULTS = eINSTANCE.getAnalysisResults();

        /**
         * The meta object literal for the '<em><b>Scenariooutput</b></em>' containment reference list feature.
         * <!-- begin-user-doc -->
         * <!-- end-user-doc -->
         * @generated
         */
        EReference ANALYSIS_RESULTS__SCENARIOOUTPUT = eINSTANCE.getAnalysisResults_Scenariooutput();

    }

} //OutputmodelPackage
