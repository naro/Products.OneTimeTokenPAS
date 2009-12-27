from Products.Archetypes.tests.atsitetestcase import ATSiteTestCase


class TokenStorageTestCase(ATSiteTestCase):
    
    def afterSetUp(self):
        pass

    def test_foo(self):
        pass

def test_suite():
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(TokenStorageTestCase))
    return suite

