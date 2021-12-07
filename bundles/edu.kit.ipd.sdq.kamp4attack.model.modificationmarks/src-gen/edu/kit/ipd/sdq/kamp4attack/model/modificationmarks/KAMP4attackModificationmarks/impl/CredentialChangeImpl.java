/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.impl.ChangePropagationStepImpl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedData;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.DatamodelContainer;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ServiceRestrictionContainer;

import java.util.Collection;

import org.eclipse.emf.common.notify.Notification;
import org.eclipse.emf.common.notify.NotificationChain;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;

import org.eclipse.emf.ecore.impl.ENotificationImpl;

import org.eclipse.emf.ecore.util.EObjectContainmentEList;
import org.eclipse.emf.ecore.util.InternalEList;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Credential Change</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl#getCompromisedresource <em>Compromisedresource</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl#getCompromisedassembly <em>Compromisedassembly</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl#getContextchange <em>Contextchange</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl#isChanged <em>Changed</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl#getCompromisedlinkingresource <em>Compromisedlinkingresource</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl#getCompromisedservice <em>Compromisedservice</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl#getServicerestrictioncontainer <em>Servicerestrictioncontainer</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl#getCompromiseddata <em>Compromiseddata</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl#getDatamodelcontainer <em>Datamodelcontainer</em>}</li>
 * </ul>
 *
 * @generated
 */
public class CredentialChangeImpl extends ChangePropagationStepImpl implements CredentialChange
{
	/**
	 * The cached value of the '{@link #getCompromisedresource() <em>Compromisedresource</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getCompromisedresource()
	 * @generated
	 * @ordered
	 */
	protected EList<CompromisedResource> compromisedresource;

	/**
	 * The cached value of the '{@link #getCompromisedassembly() <em>Compromisedassembly</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getCompromisedassembly()
	 * @generated
	 * @ordered
	 */
	protected EList<CompromisedAssembly> compromisedassembly;

	/**
	 * The cached value of the '{@link #getContextchange() <em>Contextchange</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getContextchange()
	 * @generated
	 * @ordered
	 */
	protected EList<ContextChange> contextchange;

	/**
	 * The default value of the '{@link #isChanged() <em>Changed</em>}' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #isChanged()
	 * @generated
	 * @ordered
	 */
	protected static final boolean CHANGED_EDEFAULT = false;

	/**
	 * The cached value of the '{@link #isChanged() <em>Changed</em>}' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #isChanged()
	 * @generated
	 * @ordered
	 */
	protected boolean changed = CHANGED_EDEFAULT;

	/**
	 * The cached value of the '{@link #getCompromisedlinkingresource() <em>Compromisedlinkingresource</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getCompromisedlinkingresource()
	 * @generated
	 * @ordered
	 */
	protected EList<CompromisedLinkingResource> compromisedlinkingresource;

	/**
	 * The cached value of the '{@link #getCompromisedservice() <em>Compromisedservice</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getCompromisedservice()
	 * @generated
	 * @ordered
	 */
	protected EList<CompromisedService> compromisedservice;

	/**
	 * The cached value of the '{@link #getServicerestrictioncontainer() <em>Servicerestrictioncontainer</em>}' containment reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getServicerestrictioncontainer()
	 * @generated
	 * @ordered
	 */
	protected ServiceRestrictionContainer servicerestrictioncontainer;

	/**
	 * The cached value of the '{@link #getCompromiseddata() <em>Compromiseddata</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getCompromiseddata()
	 * @generated
	 * @ordered
	 */
	protected EList<CompromisedData> compromiseddata;

	/**
	 * The cached value of the '{@link #getDatamodelcontainer() <em>Datamodelcontainer</em>}' containment reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getDatamodelcontainer()
	 * @generated
	 * @ordered
	 */
	protected DatamodelContainer datamodelcontainer;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected CredentialChangeImpl()
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
		return KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<CompromisedResource> getCompromisedresource()
	{
		if (compromisedresource == null)
		{
			compromisedresource = new EObjectContainmentEList<CompromisedResource>(CompromisedResource.class, this, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE);
		}
		return compromisedresource;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<CompromisedAssembly> getCompromisedassembly()
	{
		if (compromisedassembly == null)
		{
			compromisedassembly = new EObjectContainmentEList<CompromisedAssembly>(CompromisedAssembly.class, this, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY);
		}
		return compromisedassembly;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<ContextChange> getContextchange()
	{
		if (contextchange == null)
		{
			contextchange = new EObjectContainmentEList<ContextChange>(ContextChange.class, this, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CONTEXTCHANGE);
		}
		return contextchange;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public boolean isChanged()
	{
		return changed;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public void setChanged(boolean newChanged)
	{
		boolean oldChanged = changed;
		changed = newChanged;
		if (eNotificationRequired())
			eNotify(new ENotificationImpl(this, Notification.SET, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CHANGED, oldChanged, changed));
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<CompromisedLinkingResource> getCompromisedlinkingresource()
	{
		if (compromisedlinkingresource == null)
		{
			compromisedlinkingresource = new EObjectContainmentEList<CompromisedLinkingResource>(CompromisedLinkingResource.class, this, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE);
		}
		return compromisedlinkingresource;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<CompromisedService> getCompromisedservice()
	{
		if (compromisedservice == null)
		{
			compromisedservice = new EObjectContainmentEList<CompromisedService>(CompromisedService.class, this, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDSERVICE);
		}
		return compromisedservice;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public ServiceRestrictionContainer getServicerestrictioncontainer()
	{
		return servicerestrictioncontainer;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public NotificationChain basicSetServicerestrictioncontainer(ServiceRestrictionContainer newServicerestrictioncontainer, NotificationChain msgs)
	{
		ServiceRestrictionContainer oldServicerestrictioncontainer = servicerestrictioncontainer;
		servicerestrictioncontainer = newServicerestrictioncontainer;
		if (eNotificationRequired())
		{
			ENotificationImpl notification = new ENotificationImpl(this, Notification.SET, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER, oldServicerestrictioncontainer, newServicerestrictioncontainer);
			if (msgs == null) msgs = notification; else msgs.add(notification);
		}
		return msgs;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public void setServicerestrictioncontainer(ServiceRestrictionContainer newServicerestrictioncontainer)
	{
		if (newServicerestrictioncontainer != servicerestrictioncontainer)
		{
			NotificationChain msgs = null;
			if (servicerestrictioncontainer != null)
				msgs = ((InternalEObject)servicerestrictioncontainer).eInverseRemove(this, EOPPOSITE_FEATURE_BASE - KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER, null, msgs);
			if (newServicerestrictioncontainer != null)
				msgs = ((InternalEObject)newServicerestrictioncontainer).eInverseAdd(this, EOPPOSITE_FEATURE_BASE - KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER, null, msgs);
			msgs = basicSetServicerestrictioncontainer(newServicerestrictioncontainer, msgs);
			if (msgs != null) msgs.dispatch();
		}
		else if (eNotificationRequired())
			eNotify(new ENotificationImpl(this, Notification.SET, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER, newServicerestrictioncontainer, newServicerestrictioncontainer));
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<CompromisedData> getCompromiseddata()
	{
		if (compromiseddata == null)
		{
			compromiseddata = new EObjectContainmentEList<CompromisedData>(CompromisedData.class, this, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDDATA);
		}
		return compromiseddata;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public DatamodelContainer getDatamodelcontainer()
	{
		return datamodelcontainer;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public NotificationChain basicSetDatamodelcontainer(DatamodelContainer newDatamodelcontainer, NotificationChain msgs)
	{
		DatamodelContainer oldDatamodelcontainer = datamodelcontainer;
		datamodelcontainer = newDatamodelcontainer;
		if (eNotificationRequired())
		{
			ENotificationImpl notification = new ENotificationImpl(this, Notification.SET, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__DATAMODELCONTAINER, oldDatamodelcontainer, newDatamodelcontainer);
			if (msgs == null) msgs = notification; else msgs.add(notification);
		}
		return msgs;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public void setDatamodelcontainer(DatamodelContainer newDatamodelcontainer)
	{
		if (newDatamodelcontainer != datamodelcontainer)
		{
			NotificationChain msgs = null;
			if (datamodelcontainer != null)
				msgs = ((InternalEObject)datamodelcontainer).eInverseRemove(this, EOPPOSITE_FEATURE_BASE - KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__DATAMODELCONTAINER, null, msgs);
			if (newDatamodelcontainer != null)
				msgs = ((InternalEObject)newDatamodelcontainer).eInverseAdd(this, EOPPOSITE_FEATURE_BASE - KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__DATAMODELCONTAINER, null, msgs);
			msgs = basicSetDatamodelcontainer(newDatamodelcontainer, msgs);
			if (msgs != null) msgs.dispatch();
		}
		else if (eNotificationRequired())
			eNotify(new ENotificationImpl(this, Notification.SET, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__DATAMODELCONTAINER, newDatamodelcontainer, newDatamodelcontainer));
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public NotificationChain eInverseRemove(InternalEObject otherEnd, int featureID, NotificationChain msgs)
	{
		switch (featureID)
		{
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
				return ((InternalEList<?>)getCompromisedresource()).basicRemove(otherEnd, msgs);
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY:
				return ((InternalEList<?>)getCompromisedassembly()).basicRemove(otherEnd, msgs);
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CONTEXTCHANGE:
				return ((InternalEList<?>)getContextchange()).basicRemove(otherEnd, msgs);
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE:
				return ((InternalEList<?>)getCompromisedlinkingresource()).basicRemove(otherEnd, msgs);
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDSERVICE:
				return ((InternalEList<?>)getCompromisedservice()).basicRemove(otherEnd, msgs);
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER:
				return basicSetServicerestrictioncontainer(null, msgs);
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDDATA:
				return ((InternalEList<?>)getCompromiseddata()).basicRemove(otherEnd, msgs);
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__DATAMODELCONTAINER:
				return basicSetDatamodelcontainer(null, msgs);
		}
		return super.eInverseRemove(otherEnd, featureID, msgs);
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
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
				return getCompromisedresource();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY:
				return getCompromisedassembly();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CONTEXTCHANGE:
				return getContextchange();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CHANGED:
				return isChanged();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE:
				return getCompromisedlinkingresource();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDSERVICE:
				return getCompromisedservice();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER:
				return getServicerestrictioncontainer();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDDATA:
				return getCompromiseddata();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__DATAMODELCONTAINER:
				return getDatamodelcontainer();
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
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
				getCompromisedresource().clear();
				getCompromisedresource().addAll((Collection<? extends CompromisedResource>)newValue);
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY:
				getCompromisedassembly().clear();
				getCompromisedassembly().addAll((Collection<? extends CompromisedAssembly>)newValue);
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CONTEXTCHANGE:
				getContextchange().clear();
				getContextchange().addAll((Collection<? extends ContextChange>)newValue);
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CHANGED:
				setChanged((Boolean)newValue);
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE:
				getCompromisedlinkingresource().clear();
				getCompromisedlinkingresource().addAll((Collection<? extends CompromisedLinkingResource>)newValue);
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDSERVICE:
				getCompromisedservice().clear();
				getCompromisedservice().addAll((Collection<? extends CompromisedService>)newValue);
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER:
				setServicerestrictioncontainer((ServiceRestrictionContainer)newValue);
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDDATA:
				getCompromiseddata().clear();
				getCompromiseddata().addAll((Collection<? extends CompromisedData>)newValue);
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__DATAMODELCONTAINER:
				setDatamodelcontainer((DatamodelContainer)newValue);
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
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
				getCompromisedresource().clear();
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY:
				getCompromisedassembly().clear();
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CONTEXTCHANGE:
				getContextchange().clear();
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CHANGED:
				setChanged(CHANGED_EDEFAULT);
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE:
				getCompromisedlinkingresource().clear();
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDSERVICE:
				getCompromisedservice().clear();
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER:
				setServicerestrictioncontainer((ServiceRestrictionContainer)null);
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDDATA:
				getCompromiseddata().clear();
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__DATAMODELCONTAINER:
				setDatamodelcontainer((DatamodelContainer)null);
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
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
				return compromisedresource != null && !compromisedresource.isEmpty();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY:
				return compromisedassembly != null && !compromisedassembly.isEmpty();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CONTEXTCHANGE:
				return contextchange != null && !contextchange.isEmpty();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CHANGED:
				return changed != CHANGED_EDEFAULT;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE:
				return compromisedlinkingresource != null && !compromisedlinkingresource.isEmpty();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDSERVICE:
				return compromisedservice != null && !compromisedservice.isEmpty();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER:
				return servicerestrictioncontainer != null;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDDATA:
				return compromiseddata != null && !compromiseddata.isEmpty();
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__DATAMODELCONTAINER:
				return datamodelcontainer != null;
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
		result.append(" (changed: ");
		result.append(changed);
		result.append(')');
		return result.toString();
	}

} //CredentialChangeImpl
