//! Service detection based on well-known port numbers.
//!
//! Provides mapping from port numbers to likely service names.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Static map of well-known ports to service names.
static PORT_SERVICES: LazyLock<HashMap<u16, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    // Common TCP services
    m.insert(20, "ftp-data");
    m.insert(21, "ftp");
    m.insert(22, "ssh");
    m.insert(23, "telnet");
    m.insert(25, "smtp");
    m.insert(53, "dns");
    m.insert(67, "dhcp-server");
    m.insert(68, "dhcp-client");
    m.insert(69, "tftp");
    m.insert(80, "http");
    m.insert(88, "kerberos");
    m.insert(110, "pop3");
    m.insert(111, "rpcbind");
    m.insert(119, "nntp");
    m.insert(123, "ntp");
    m.insert(135, "msrpc");
    m.insert(137, "netbios-ns");
    m.insert(138, "netbios-dgm");
    m.insert(139, "netbios-ssn");
    m.insert(143, "imap");
    m.insert(161, "snmp");
    m.insert(162, "snmptrap");
    m.insert(179, "bgp");
    m.insert(194, "irc");
    m.insert(389, "ldap");
    m.insert(443, "https");
    m.insert(445, "microsoft-ds");
    m.insert(464, "kpasswd");
    m.insert(465, "smtps");
    m.insert(500, "isakmp");
    m.insert(513, "rlogin");
    m.insert(514, "syslog");
    m.insert(515, "printer");
    m.insert(520, "rip");
    m.insert(521, "ripng");
    m.insert(523, "ibm-db2");
    m.insert(543, "klogin");
    m.insert(544, "kshell");
    m.insert(548, "afp");
    m.insert(554, "rtsp");
    m.insert(587, "submission");
    m.insert(631, "ipp");
    m.insert(636, "ldaps");
    m.insert(873, "rsync");
    m.insert(902, "vmware-auth");
    m.insert(993, "imaps");
    m.insert(995, "pop3s");
    m.insert(1080, "socks");
    m.insert(1194, "openvpn");
    m.insert(1433, "mssql");
    m.insert(1434, "mssql-m");
    m.insert(1521, "oracle");
    m.insert(1701, "l2tp");
    m.insert(1723, "pptp");
    m.insert(1812, "radius");
    m.insert(1813, "radius-acct");
    m.insert(1883, "mqtt");
    m.insert(2049, "nfs");
    m.insert(2082, "cpanel");
    m.insert(2083, "cpanel-ssl");
    m.insert(2086, "whm");
    m.insert(2087, "whm-ssl");
    m.insert(2181, "zookeeper");
    m.insert(2375, "docker");
    m.insert(2376, "docker-ssl");
    m.insert(3000, "grafana");
    m.insert(3128, "squid");
    m.insert(3268, "globalcat");
    m.insert(3269, "globalcat-ssl");
    m.insert(3306, "mysql");
    m.insert(3389, "rdp");
    m.insert(3690, "svn");
    m.insert(4369, "epmd");
    m.insert(4443, "pharos");
    m.insert(5000, "upnp");
    m.insert(5060, "sip");
    m.insert(5061, "sips");
    m.insert(5222, "xmpp-client");
    m.insert(5269, "xmpp-server");
    m.insert(5432, "postgresql");
    m.insert(5672, "amqp");
    m.insert(5900, "vnc");
    m.insert(5984, "couchdb");
    m.insert(6379, "redis");
    m.insert(6443, "kubernetes-api");
    m.insert(6666, "irc");
    m.insert(6667, "irc");
    m.insert(7001, "weblogic");
    m.insert(7077, "spark-master");
    m.insert(8000, "http-alt");
    m.insert(8008, "http-alt");
    m.insert(8080, "http-proxy");
    m.insert(8081, "http-alt");
    m.insert(8082, "http-alt");
    m.insert(8083, "http-alt");
    m.insert(8443, "https-alt");
    m.insert(8888, "http-alt");
    m.insert(9000, "cslistener");
    m.insert(9042, "cassandra");
    m.insert(9090, "prometheus");
    m.insert(9092, "kafka");
    m.insert(9200, "elasticsearch");
    m.insert(9300, "elasticsearch-cluster");
    m.insert(9418, "git");
    m.insert(10000, "webmin");
    m.insert(11211, "memcached");
    m.insert(15672, "rabbitmq-mgmt");
    m.insert(27017, "mongodb");
    m.insert(27018, "mongodb");
    m.insert(27019, "mongodb");
    m.insert(28017, "mongodb-web");
    m.insert(50000, "db2");
    m.insert(50070, "hdfs-namenode");
    m.insert(50075, "hdfs-datanode");

    m
});

/// Look up the probable service name for a given port.
///
/// Returns `None` if the port is not in the well-known services database.
pub fn get_service_name(port: u16) -> Option<&'static str> {
    PORT_SERVICES.get(&port).copied()
}

/// Get a descriptive string for the service on a port.
///
/// Returns "unknown" if the port is not recognized.
pub fn get_service_description(port: u16) -> &'static str {
    get_service_name(port).unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_ports() {
        assert_eq!(get_service_name(22), Some("ssh"));
        assert_eq!(get_service_name(80), Some("http"));
        assert_eq!(get_service_name(443), Some("https"));
        assert_eq!(get_service_name(3306), Some("mysql"));
    }

    #[test]
    fn test_unknown_port() {
        assert_eq!(get_service_name(12345), None);
        assert_eq!(get_service_description(12345), "unknown");
    }
}
