package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import java.util.Collection;
import java.util.List;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;

public abstract class Change<T> {
    
    protected Collection<T> initialMarkedItems;
    
	protected BlackboardWrapper modelStorage;
	
	public Change(BlackboardWrapper v) {
		modelStorage = v;
		initialMarkedItems = loadInitialMarkedItems();
	}
	
	protected abstract Collection<T> loadInitialMarkedItems();
}
