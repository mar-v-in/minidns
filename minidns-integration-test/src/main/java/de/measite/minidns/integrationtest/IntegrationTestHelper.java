/*
 * Copyright 2015 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.integrationtest;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class IntegrationTestHelper {
    private static Set<Class<?>> testClasses;
    private static Logger LOGGER = Logger.getLogger("Test");

    static {
        testClasses = new HashSet<>();
        testClasses.add(CoreTest.class);
        testClasses.add(DNSSECTest.class);
        testClasses.add(DaneTest.class);
    }

    public static void main(String[] args) throws IllegalAccessException {
        for (final Class<?> aClass : testClasses) {
            for (final Method method : aClass.getDeclaredMethods()) {
                if (method.isAnnotationPresent(IntegrationTest.class)) {
                    invokeTest(method, aClass);
                }
            }
        }
    }

    public static void invokeTest(Method method, Class<?> aClass) {
        String methodName = aClass.getName() + "." + method.getName() + "()";
        Class<?> expected = method.getAnnotation(IntegrationTest.class).expected();
        if (!Exception.class.isAssignableFrom(expected)) expected = null;

        try {
            method.invoke(null);

            if (expected != null) {
                LOGGER.logp(Level.WARNING, aClass.getName(), method.getName(), "Test failed: expected exception " + expected + " was not thrown!");
            } else {
                LOGGER.logp(Level.INFO, aClass.getName(), method.getName(), "Test suceeded.");
            }
        } catch (InvocationTargetException e) {
            if (expected != null && expected.isAssignableFrom(e.getTargetException().getClass())) {
                LOGGER.logp(Level.INFO, aClass.getName(), method.getName(), "Test suceeded.");
            } else {
                LOGGER.logp(Level.WARNING, aClass.getName(), method.getName(), "Test failed: unexpected exception was thrown: ", e.getTargetException());
            }
        } catch (IllegalAccessException | NullPointerException e) {
            LOGGER.logp(Level.SEVERE, aClass.getName(), method.getName(), "Test failed: could not invoke test, is it public static?");
        }
    }

    public static void assertEquals(Object a, Object b) {
        if ((a == null && b != null) || (a != null && !a.equals(b)))
            throw new IllegalStateException("Test failed: " + a + " != " + b);
    }

    public static void assertNotEquals(Object a, Object b) {
        if ((a == null && b == null) || (a != null && a.equals(b)))
            throw new IllegalStateException("Test failed: " + a + " == " + b);
    }

    public static void assertTrue(Object actual) {
        assertEquals(true, actual);
    }

    public static void assertFalse(Object actual) {
        assertEquals(false, actual);
    }

    public static void assertNull(Object actual) {
        assertEquals(null, actual);
    }

    public static void assertNotNull(Object actual) {
        assertNotEquals(null, actual);
    }
}
