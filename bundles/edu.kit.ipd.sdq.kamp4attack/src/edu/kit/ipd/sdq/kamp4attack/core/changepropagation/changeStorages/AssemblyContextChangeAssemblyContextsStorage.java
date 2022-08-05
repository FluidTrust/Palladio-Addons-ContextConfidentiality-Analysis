package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changeStorages;

import java.util.HashMap;
import java.util.List;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public class AssemblyContextChangeAssemblyContextsStorage {

	private static AssemblyContextChangeAssemblyContextsStorage singleton;

	private HashMap<String, List<AssemblyContext>> assemblyContextsMap;

	private AssemblyContextChangeAssemblyContextsStorage() {
		assemblyContextsMap = new HashMap<>();
	}

	public static synchronized AssemblyContextChangeAssemblyContextsStorage getInstance() {
		if (singleton == null) {
			singleton = new AssemblyContextChangeAssemblyContextsStorage();
		}

		return singleton;
	}

	public void reset() {
		assemblyContextsMap = new HashMap<>();
		assemblyContextsMap.clear();
	}

	// IMPORTANT: HashMap is unsynchronized, so synchronization must be done here.
	public synchronized void put(String key, List<AssemblyContext> value) {
		assemblyContextsMap.put(key, value);
	}

	public List<AssemblyContext> get(String key) {
		return assemblyContextsMap.get(key);
	}

	public boolean contains(String key) {
		return assemblyContextsMap.containsKey(key);
	}
}
