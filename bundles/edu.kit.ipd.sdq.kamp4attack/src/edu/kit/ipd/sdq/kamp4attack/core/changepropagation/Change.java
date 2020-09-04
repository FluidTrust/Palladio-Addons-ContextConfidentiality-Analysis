package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;

public abstract class Change {
	protected BlackboardWrapper version;
	
	public Change(BlackboardWrapper v) {
		version = v;
	}
}
