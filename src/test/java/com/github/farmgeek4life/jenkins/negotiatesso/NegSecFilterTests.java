package com.github.farmgeek4life.jenkins.negotiatesso;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class NegSecFilterTests {
	
	
	
	@Test
	public void test_should_require_security() {
		assertTrue(NegSecFilter.requiresAuthentication("jenkins", "job/SomeJob"));
		assertTrue(NegSecFilter.requiresAuthentication("", 		"job/SomeJob"));
		assertTrue(NegSecFilter.requiresAuthentication("jenkins", "job/notifyCommit"));
	}
	
	@Test
	public void test_should_not_require_security() {
		assertFalse(NegSecFilter.requiresAuthentication("jenkins", 	"jenkins/cli"));
		assertFalse(NegSecFilter.requiresAuthentication("", 			"cli"));
		assertFalse(NegSecFilter.requiresAuthentication("jenkins", 	"jenkins/userContent"));
		assertFalse(NegSecFilter.requiresAuthentication("", 			"userContent"));
		assertFalse(NegSecFilter.requiresAuthentication("jenkins",	"jenkins/jnlpJars"));
		assertFalse(NegSecFilter.requiresAuthentication("", 			"jnlpJars"));
		assertFalse(NegSecFilter.requiresAuthentication("jenkins", 	"jenkins/whoAmI"));
		assertFalse(NegSecFilter.requiresAuthentication("", 			"whoAmI"));
		assertFalse(NegSecFilter.requiresAuthentication("jenkins", 	"jenkins/login"));
		assertFalse(NegSecFilter.requiresAuthentication("", 			"login"));

		assertFalse(NegSecFilter.requiresAuthentication("jenkins", 	"jenkins/git/notifyCommit"));
		assertFalse(NegSecFilter.requiresAuthentication("", 			"git/notifyCommit"));
		assertFalse(NegSecFilter.requiresAuthentication("jenkins", 	"jenkins/subversion/notifyCommit"));
		assertFalse(NegSecFilter.requiresAuthentication("", 			"subversion/notifyCommit"));
		assertFalse(NegSecFilter.requiresAuthentication("jenkins", 	"jenkins/mercurial/notifyCommit"));
		assertFalse(NegSecFilter.requiresAuthentication("", 			"mercurial/notifyCommit"));
		
	}
	
}
