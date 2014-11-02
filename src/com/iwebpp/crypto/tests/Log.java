package com.iwebpp.crypto.tests;

public final class Log {

	public static void d(String tag, String message) {
		System.out.println(tag+":debug:" + message);
	}
	
	public static void e(String tag, String message) {
		System.out.println(tag+":error:" + message);
	}
	
}
