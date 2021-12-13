/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssemblyContainer;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

import java.util.Collection;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;

import org.eclipse.emf.ecore.impl.MinimalEObjectImpl;

import org.eclipse.emf.ecore.util.EObjectResolvingEList;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Compromised Assembly Container</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedAssemblyContainerImpl#getAffectedElements <em>Affected Elements</em>}</li>
 * </ul>
 *
 * @generated
 */
public class CompromisedAssemblyContainerImpl extends MinimalEObjectImpl.Container implements CompromisedAssemblyContainer {
	/**
	 * The cached value of the '{@link #getAffectedElements() <em>Affected Elements</em>}' reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getAffectedElements()
	 * @generated
	 * @ordered
	 */
	protected EList<CompromisedAssembly> affectedElements;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected CompromisedAssemblyContainerImpl() {
		super();
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	protected EClass eStaticClass() {
		return KAMP4attackModificationmarksPackage.Literals.COMPROMISED_ASSEMBLY_CONTAINER;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<CompromisedAssembly> getAffectedElements() {
		if (affectedElements == null) {
			affectedElements = new EObjectResolvingEList<CompromisedAssembly>(CompromisedAssembly.class, this, KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY_CONTAINER__AFFECTED_ELEMENTS);
		}
		return affectedElements;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public Object eGet(int featureID, boolean resolve, boolean coreType) {
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY_CONTAINER__AFFECTED_ELEMENTS:
				return getAffectedElements();
		}
		return super.eGet(featureID, resolve, coreType);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void eSet(int featureID, Object newValue) {
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY_CONTAINER__AFFECTED_ELEMENTS:
				getAffectedElements().clear();
				getAffectedElements().addAll((Collection<? extends CompromisedAssembly>)newValue);
				return;
		}
		super.eSet(featureID, newValue);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public void eUnset(int featureID) {
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY_CONTAINER__AFFECTED_ELEMENTS:
				getAffectedElements().clear();
				return;
		}
		super.eUnset(featureID);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public boolean eIsSet(int featureID) {
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY_CONTAINER__AFFECTED_ELEMENTS:
				return affectedElements != null && !affectedElements.isEmpty();
		}
		return super.eIsSet(featureID);
	}

} //CompromisedAssemblyContainerImpl
