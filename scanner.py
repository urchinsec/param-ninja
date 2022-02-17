class Scanner:

  def full_scan(self, url):
    return {
      "checked_url": url,
      "technology": self.scan_for_technologies(url),
      "vuln": self.scan_for_vuln(url),
      "server_version": self.scan_for_server_version(url)
    }

  def scan_for_technologies(self, url):
    return "Windows"

  def scan_for_vuln(self, url):
    return "RCE found"
  
  def scan_for_server_version(self, url):
    return "Server 2009"