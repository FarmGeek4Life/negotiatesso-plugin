package com.github.farmgeek4life.jenkins.negotiatesso;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class NegSecFilterTests {
	
	
	
	@Test
	public void test_should_require_security() {
		assertTrue(NegSecFilter.requiresSecurity("jenkins", "job/SomeJob"));
		assertTrue(NegSecFilter.requiresSecurity("", 		"job/SomeJob"));
		assertTrue(NegSecFilter.requiresSecurity("jenkins", "job/notifyCommit"));
	}
	
	@Test
	public void test_should_not_require_security() {
		assertFalse(NegSecFilter.requiresSecurity("jenkins", 	"jenkins/cli"));
		assertFalse(NegSecFilter.requiresSecurity("", 			"cli"));
		assertFalse(NegSecFilter.requiresSecurity("jenkins", 	"jenkins/userContent"));
		assertFalse(NegSecFilter.requiresSecurity("", 			"userContent"));
		assertFalse(NegSecFilter.requiresSecurity("jenkins",	"jenkins/jnlpJars"));
		assertFalse(NegSecFilter.requiresSecurity("", 			"jnlpJars"));
		assertFalse(NegSecFilter.requiresSecurity("jenkins", 	"jenkins/whoAmI"));
		assertFalse(NegSecFilter.requiresSecurity("", 			"whoAmI"));
		assertFalse(NegSecFilter.requiresSecurity("jenkins", 	"jenkins/login"));
		assertFalse(NegSecFilter.requiresSecurity("", 			"login"));

		assertFalse(NegSecFilter.requiresSecurity("jenkins", 	"jenkins/git/notifyCommit"));
		assertFalse(NegSecFilter.requiresSecurity("", 			"git/notifyCommit"));
		assertFalse(NegSecFilter.requiresSecurity("jenkins", 	"jenkins/subversion/notifyCommit"));
		assertFalse(NegSecFilter.requiresSecurity("", 			"subversion/notifyCommit"));
		assertFalse(NegSecFilter.requiresSecurity("jenkins", 	"jenkins/mercurial/notifyCommit"));
		assertFalse(NegSecFilter.requiresSecurity("", 			"mercurial/notifyCommit"));
		
	}
	
}
