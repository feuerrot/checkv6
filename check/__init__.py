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
	
	def __filter_mx(self, mx):
		return mx

	def _query(self, type, hostname=None):
		if type == dns.rdatatype.MX:
			hostname = self.__filter_mx(hostname or self.hostname)
		return dns.resolver.query(hostname or self.hostname, type)
	
	def _aaaa(self, hostname=None):
		query = self._query(dns.rdatatype.AAAA, hostname)
		return [answer for answer in query.rrset]
	
	def _ns(self, hostname=None):
		query = self._query(dns.rdatatype.NS)
		ns_set = {}
		for ns in query.rrset:
			try:
				ns_set[ns] = self._aaaa(ns.to_text())
			except dns.resolver.NoAnswer:
				self._debug("nameserver", ns, "has no AAAA record", level="!")

		return ns_set
	
	def _mx(self):
		query = self._query(dns.rdatatype.MX)
		mx_set = {}
		for mx in query.rrset:
			try:
				mx_set[mx] = self._aaaa(mx.exchange.to_text())
			except dns.resolver.NoAnswer:
				self._debug("mailexchange", mx, "has no AAAA record", level="!")
			except dns.resolver.NXDOMAIN:
				self._debug("NXDOMAIN", mx.exchange)

		return mx_set
	
	def _http(self):
		pass
	
	def _https(self):
		pass

if __name__ == "__main__":
	c = Check("ccc.de")
	print(c._ns())
	print(c._mx())
	c = Check("heise.de")
	print(c._ns())
	print(c._mx())
