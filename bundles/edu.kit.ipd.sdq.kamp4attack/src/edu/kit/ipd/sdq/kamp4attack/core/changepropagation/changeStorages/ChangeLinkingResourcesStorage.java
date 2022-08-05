package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changeStorages;

import java.util.HashMap;
import java.util.List;

import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;

public class ChangeLinkingResourcesStorage {

	private static ChangeLinkingResourcesStorage singleton;

	private HashMap<String, List<LinkingResource>> linkingResourcesMap;

	private ChangeLinkingResourcesStorage() {
		linkingResourcesMap = new HashMap<>();
	}

	public static synchronized ChangeLinkingResourcesStorage getInstance() {
		if (singleton == null) {
			singleton = new ChangeLinkingResourcesStorage();
		}

		return singleton;
	}

	public void reset() {
		linkingResourcesMap = new HashMap<>();
		linkingResourcesMap.clear();
	}

	// IMPORTANT: HashMap is unsynchronized, so synchronization must be done here.
	public synchronized void put(String key, List<LinkingResource> value) {
		linkingResourcesMap.put(key, value);
	}

	public List<LinkingResource> get(String key) {
		return linkingResourcesMap.get(key);
	}

	public boolean contains(String key) {
		return linkingResourcesMap.containsKey(key);
	}

}
