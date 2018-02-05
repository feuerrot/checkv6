#!/usr/bin/env python
import dns.resolver
import dns.name
import requests

class Check:
	def __init__(self, hostname):
		self.hostname = dns.name.from_text(hostname)
		self.resolver = dns.resolver.Resolver()
		self._check_cname()
		self.result = {}

	def _query(self, record, hostname=None):
		query = self.resolver.query(hostname or self.hostname, record)
		return [answer for answer in query]

	def _check_cname(self):
		try:
			query = self.resolver.query(
				self.hostname,
				dns.rdatatype.CNAME
				)
		except dns.resolver.NoAnswer:
			return

		# nopenopenope, we do not support more than one cname
		self.hostname = query[0].target
	
	def _get_soa(self):
		self.soa = None
		query = self.resolver.query(
			self.hostname,
			dns.rdatatype.SOA,
			raise_on_no_answer=False
		)

		try:
			self.soa = query.rrset.name
		except AttributeError:
			pass
		try:
			self.soa = query.response.authority[0].name
		except IndexError:
			pass

		if self.soa == None:
			raise Exception
	
	def _get_first_record(self, record, hostname):
		self._get_soa()
		assert(self.soa.is_superdomain(hostname))

		while self.soa.is_superdomain(hostname):
			try:
				result = self._query(record, hostname)
				return result
			except dns.resolver.NoAnswer:
				hostname = hostname.parent()

		raise dns.resolver.NoAnswer
	
	def _aaaa(self, hostname=None):
		try:
			return self._query(dns.rdatatype.AAAA, hostname)
		except dns.resolver.NoAnswer:
			return []
	
	def _ns(self):
		query = self._get_first_record(dns.rdatatype.NS, self.hostname)
		return [elem for answer in query for elem in self._aaaa(answer.target)]
	
	def _mx(self):
		try:
			query = self._get_first_record(dns.rdatatype.MX, self.hostname)
		except dns.resolver.NoAnswer:
			return None
		return [elem for answer in query for elem in self._aaaa(answer.exchange)]
	
	def check(self):
		self.result["ns"] = self._ns()
		self.result["mx"] = self._mx()
		self.result["aaaa"] = self._aaaa()
		return self.result
	
if __name__ == "__main__":
	c = Check("www.chaosdorf.de")
	print(c.check())
	c = Check("www.ccc.de")
	print(c.check())
	c = Check("www.duesseldorf.ccc.de")
	print(c.check())
	c = Check("check.ipv6only.network")
	print(c.check())
