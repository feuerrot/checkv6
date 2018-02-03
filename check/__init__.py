#!/usr/bin/env python
import dns.resolver
import requests

class Check:
	debug = True
	
	def __init__(self, hostname):
		self.hostname = hostname
	
	def _debug(self, *args, level=None):
		if self.debug:
			print(
				"[{}]".format(level or "x"),
				" ".join([str(arg) for arg in args])
			)
	
	def _query(self, type, hostname=None):
		return dns.resolver.query(hostname or self.hostname, type)
	
	def _aaaa(self, hostname=None):
		query = self._query('AAAA', hostname)
		
		return [answer.to_text() for answer in query.rrset]
	
	def _ns(self, hostname=None):
		query = self._query('NS')
		ns_set = {}
		for ns in query.rrset:
			try:
				ns_set[ns.to_text()] = self._aaaa(ns.to_text())
			except dns.resolver.NoAnswer:
				self._debug("nameserver", ns, "has no AAAA record", level="!")
				#ns_set[ns] = None
		print(ns_set)
	
	def _mx(self):
		pass
	
	def _http(self):
		pass
	
	def _https(self):
		pass

if __name__ == "__main__":
	c = Check("heise.de")
	c._ns()
