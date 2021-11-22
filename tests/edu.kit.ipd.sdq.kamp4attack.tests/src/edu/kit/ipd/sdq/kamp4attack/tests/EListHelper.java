package edu.kit.ipd.sdq.kamp4attack.tests;

import java.util.Arrays;

import org.eclipse.emf.common.util.BasicEList;
import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EObject;

public class EListHelper {
    private EListHelper() {

    }

    public static <T extends EObject> EList<T> of(T... element) {
        var list = new BasicEList<T>();
        Arrays.stream(element).forEach(list::add);
        return list;
    }

}
