#!/usr/bin/env python
import dns.resolver
import dns.name
import requests

class Check:
	debug = True
	
	def __init__(self, hostname):
		self.hostname = dns.name.from_text(hostname)
		self.resolver = dns.resolver.Resolver()
		#self.resolver.nameservers = ["::1", "127.0.0.1"]
		self.result = {}
	
	def _debug(self, *args, level=None):
		if self.debug:
			print(
				"[{}]".format(level or "x"),
				" ".join([str(arg) for arg in args])
			)

	def _query(self, record, hostname=None):
		query = self.resolver.query(hostname or self.hostname, record)
		return [answer for answer in query]
	
	def _get_first_record(self, record, hostname):
		self._get_soa()
		assert(self.soa.is_superdomain(hostname))

		while self.soa.is_superdomain(hostname):
			try:
				result = self._query(record, hostname)
				return result
			except dns.resolver.NoAnswer:
				hostname = hostname.parent()

		return None
	
	def _aaaa(self, hostname=None):
		return self._query(dns.rdatatype.AAAA, hostname)
	
	def _ns(self):
		query = self._get_first_record(dns.rdatatype.NS, self.hostname)
		return [answer.target for answer in query]
	
	def _mx(self):
		query = self._get_first_record(dns.rdatatype.MX, self.hostname)
		return [answer.exchange for answer in query]

	def _get_soa(self):
		query = self.resolver.query(
			self.hostname,
			dns.rdatatype.SOA,
			raise_on_no_answer=False
		)
		self.soa = query.response.authority[0].name
	
	def _http(self):
		pass
	
	def _https(self):
		pass
	
	def check(self):
		self.result["ns"] = self._ns()
		self.result["mx"] = self._mx()
		self.result["aaaa"] = self._aaaa()
		return self.result
	
if __name__ == "__main__":
	c = Check("www.chaosdorf.de")
	print(c.check())
