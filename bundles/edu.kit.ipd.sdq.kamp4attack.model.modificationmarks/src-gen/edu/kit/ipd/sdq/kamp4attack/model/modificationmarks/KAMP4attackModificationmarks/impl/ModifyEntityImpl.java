/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import de.uka.ipd.sdq.identifier.impl.IdentifierImpl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;

import java.util.Collection;

import org.eclipse.emf.common.notify.Notification;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.InternalEObject;

import org.eclipse.emf.ecore.impl.ENotificationImpl;

import org.eclipse.emf.ecore.util.EObjectResolvingEList;

import org.palladiosimulator.pcm.core.entity.Entity;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Modify Entity</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ModifyEntityImpl#isToolderived <em>Toolderived</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ModifyEntityImpl#getAffectedElement <em>Affected Element</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ModifyEntityImpl#getCausingElements <em>Causing Elements</em>}</li>
 * </ul>
 *
 * @generated
 */
public abstract class ModifyEntityImpl<T extends Entity> extends IdentifierImpl implements ModifyEntity<T>
{
	/**
	 * The default value of the '{@link #isToolderived() <em>Toolderived</em>}' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #isToolderived()
	 * @generated
	 * @ordered
	 */
	protected static final boolean TOOLDERIVED_EDEFAULT = false;

	/**
	 * The cached value of the '{@link #isToolderived() <em>Toolderived</em>}' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #isToolderived()
	 * @generated
	 * @ordered
	 */
	protected boolean toolderived = TOOLDERIVED_EDEFAULT;

	/**
	 * The cached value of the '{@link #getAffectedElement() <em>Affected Element</em>}' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getAffectedElement()
	 * @generated
	 * @ordered
	 */
	protected T affectedElement;

	/**
	 * The cached value of the '{@link #getCausingElements() <em>Causing Elements</em>}' reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getCausingElements()
	 * @generated
	 * @ordered
	 */
	protected EList<EObject> causingElements;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected ModifyEntityImpl()
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
		return KAMP4attackModificationmarksPackage.Literals.MODIFY_ENTITY;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public boolean isToolderived()
	{
		return toolderived;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public void setToolderived(boolean newToolderived)
	{
		boolean oldToolderived = toolderived;
		toolderived = newToolderived;
		if (eNotificationRequired())
			eNotify(new ENotificationImpl(this, Notification.SET, KAMP4attackModificationmarksPackage.MODIFY_ENTITY__TOOLDERIVED, oldToolderived, toolderived));
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@SuppressWarnings("unchecked")
	public T getAffectedElement()
	{
		if (affectedElement != null && affectedElement.eIsProxy())
		{
			InternalEObject oldAffectedElement = (InternalEObject)affectedElement;
			affectedElement = (T)eResolveProxy(oldAffectedElement);
			if (affectedElement != oldAffectedElement)
			{
				if (eNotificationRequired())
					eNotify(new ENotificationImpl(this, Notification.RESOLVE, KAMP4attackModificationmarksPackage.MODIFY_ENTITY__AFFECTED_ELEMENT, oldAffectedElement, affectedElement));
			}
		}
		return affectedElement;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public T basicGetAffectedElement()
	{
		return affectedElement;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public void setAffectedElement(T newAffectedElement)
	{
		T oldAffectedElement = affectedElement;
		affectedElement = newAffectedElement;
		if (eNotificationRequired())
			eNotify(new ENotificationImpl(this, Notification.SET, KAMP4attackModificationmarksPackage.MODIFY_ENTITY__AFFECTED_ELEMENT, oldAffectedElement, affectedElement));
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<EObject> getCausingElements()
	{
		if (causingElements == null)
		{
			causingElements = new EObjectResolvingEList<EObject>(EObject.class, this, KAMP4attackModificationmarksPackage.MODIFY_ENTITY__CAUSING_ELEMENTS);
		}
		return causingElements;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public Object eGet(int featureID, boolean resolve, boolean coreType)
	{
		switch (featureID)
		{
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__TOOLDERIVED:
				return isToolderived();
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__AFFECTED_ELEMENT:
				if (resolve) return getAffectedElement();
				return basicGetAffectedElement();
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__CAUSING_ELEMENTS:
				return getCausingElements();
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
	public void eSet(int featureID, Object newValue)
	{
		switch (featureID)
		{
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__TOOLDERIVED:
				setToolderived((Boolean)newValue);
				return;
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__AFFECTED_ELEMENT:
				setAffectedElement((T)newValue);
				return;
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__CAUSING_ELEMENTS:
				getCausingElements().clear();
				getCausingElements().addAll((Collection<? extends EObject>)newValue);
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
	public void eUnset(int featureID)
	{
		switch (featureID)
		{
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__TOOLDERIVED:
				setToolderived(TOOLDERIVED_EDEFAULT);
				return;
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__AFFECTED_ELEMENT:
				setAffectedElement((T)null);
				return;
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__CAUSING_ELEMENTS:
				getCausingElements().clear();
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
	public boolean eIsSet(int featureID)
	{
		switch (featureID)
		{
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__TOOLDERIVED:
				return toolderived != TOOLDERIVED_EDEFAULT;
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__AFFECTED_ELEMENT:
				return affectedElement != null;
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY__CAUSING_ELEMENTS:
				return causingElements != null && !causingElements.isEmpty();
		}
		return super.eIsSet(featureID);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public String toString()
	{
		if (eIsProxy()) return super.toString();

		StringBuilder result = new StringBuilder(super.toString());
		result.append(" (toolderived: ");
		result.append(toolderived);
		result.append(')');
		return result.toString();
	}

} //ModifyEntityImpl
